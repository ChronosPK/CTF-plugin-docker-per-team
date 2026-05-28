import json

from flask import Blueprint, Flask

from CTFd.models import db
from CTFd.exceptions.challenges import ChallengeCreateException, ChallengeUpdateException
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES
from CTFd.plugins.dynamic_score.scoring import sync_dynamic_awards
from CTFd.plugins.migrations import upgrade

from .admin_routes import admin_bp, set_container_manager as set_admin_manager
from .container_manager import ContainerManager
from .helpers import (
    find_active_container,
    get_container_flag,
    parse_capabilities_value,
    get_settings_path,
    get_xid_and_flag,
    seed_default_settings,
    settings_to_dict,
)
from .models import (
    ContainerChallengeModel,
    ContainerSettingsModel,
)
from .user_routes import containers_bp, set_container_manager as set_user_manager

settings = json.load(open(get_settings_path()))
container_manager = None


def _normalize_challenge_payload(data, *, creation):
    if not data:
        exc = ChallengeCreateException if creation else ChallengeUpdateException
        raise exc("Challenge payload is empty")

    exc = ChallengeCreateException if creation else ChallengeUpdateException
    allowed_fields = set(ContainerChallengeModel.__mapper__.columns.keys()) - {"id", "value"}
    normalized = {}

    for attr, raw_value in data.items():
        if attr not in allowed_fields:
            continue

        value = raw_value.strip() if isinstance(raw_value, str) else raw_value

        try:
            if attr in {"initial", "minimum", "decay", "port", "random_flag_length"}:
                value = int(value)
            elif attr in {"connection_type", "flag_mode"}:
                value = str(value).strip().lower()
            elif attr in {"volumes", "capabilities"}:
                value = "" if value is None else str(value).strip()
            elif isinstance(value, str):
                value = value.strip()
        except (TypeError, ValueError):
            raise exc(f"Invalid input for '{attr}'")

        normalized[attr] = value

    required_fields = {
        "name",
        "category",
        "description",
        "state",
        "type",
        "image",
        "port",
        "connection_type",
        "initial",
        "minimum",
        "decay",
        "flag_mode",
    }
    missing = sorted(field for field in required_fields if creation and not normalized.get(field))
    if missing:
        raise exc(f"Missing required fields: {', '.join(missing)}")

    if "type" in normalized and normalized["type"] != "container":
        raise exc("Container challenges must have type 'container'")
    if "port" in normalized and not (1 <= normalized["port"] <= 65535):
        raise exc("Port must be between 1 and 65535")
    if "initial" in normalized and normalized["initial"] < 0:
        raise exc("Initial value must be zero or greater")
    if "minimum" in normalized and normalized["minimum"] < 0:
        raise exc("Minimum value must be zero or greater")
    if "initial" in normalized and "minimum" in normalized and normalized["minimum"] > normalized["initial"]:
        raise exc("Minimum value cannot exceed initial value")
    if "decay" in normalized and not (1 <= normalized["decay"] <= 100):
        raise exc("Decay must be between 1 and 100")
    if "random_flag_length" in normalized and not (1 <= normalized["random_flag_length"] <= 128):
        raise exc("Random flag length must be between 1 and 128")
    if "connection_type" in normalized and normalized["connection_type"] not in {"tcp", "web"}:
        raise exc("Connection type must be either 'tcp' or 'web'")
    if "flag_mode" in normalized and normalized["flag_mode"] not in {"static", "random"}:
        raise exc("Flag mode must be either 'static' or 'random'")

    for attr in {"volumes", "capabilities"}:
        value = normalized.get(attr, "")
        if not value:
            continue
        if attr == "volumes":
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                raise exc("Volumes must be valid JSON")
            if not isinstance(parsed, dict):
                raise exc("Volumes must be a JSON object")
        elif value.startswith("["):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                raise exc("Capabilities JSON string is invalid")
            if not isinstance(parsed, list):
                raise exc("Capabilities JSON must be an array of strings")

    effective_settings = settings_to_dict(ContainerSettingsModel.query.all())

    volumes_enabled = effective_settings.get("allow_challenge_volumes", "disabled") == "enabled"
    if normalized.get("volumes") and not volumes_enabled:
        raise exc("Challenge volume mounts are disabled by plugin settings")

    capabilities_value = normalized.get("capabilities", "")
    if capabilities_value:
        try:
            requested_capabilities = parse_capabilities_value(capabilities_value)
            allowed_capabilities = set(
                parse_capabilities_value(effective_settings.get("allowed_capabilities", ""))
            )
        except ValueError as err:
            raise exc(str(err))

        if not allowed_capabilities:
            raise exc("Extra Linux capabilities are disabled by plugin settings")

        disallowed_capabilities = [
            capability for capability in requested_capabilities if capability not in allowed_capabilities
        ]
        if disallowed_capabilities:
            raise exc(
                "Capabilities are not allowed by plugin settings: "
                + ", ".join(disallowed_capabilities)
            )

    return normalized


class ContainerChallenge(BaseChallenge):
    id = settings["plugin-info"]["id"]
    name = settings["plugin-info"]["name"]
    templates = settings["plugin-info"]["templates"]
    scripts = settings["plugin-info"]["scripts"]
    route = settings["plugin-info"]["base_path"]
    challenge_model = ContainerChallengeModel

    @classmethod
    def read(cls, challenge):
        return {
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "image": challenge.image,
            "port": challenge.port,
            "command": challenge.command,
            "volumes": challenge.volumes,
            "capabilities": challenge.capabilities,
            "connection_type": challenge.connection_type,
            "initial": challenge.initial,
            "decay": challenge.decay,
            "minimum": challenge.minimum,
            "description": challenge.description,
            "connection_info": challenge.connection_info,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "flag_mode": challenge.flag_mode,
            "flag_prefix": challenge.flag_prefix,
            "flag_suffix": challenge.flag_suffix,
            "random_flag_length": challenge.random_flag_length,
            "type": challenge.type,
            "type_data": {
                "id": cls.id,
                "name": cls.name,
                "templates": cls.templates,
                "scripts": cls.scripts,
            },
        }

    @classmethod
    def calculate_value(cls, challenge):
        return sync_dynamic_awards(challenge)

    @classmethod
    def create(cls, request):
        data = request.form or request.get_json()
        normalized = _normalize_challenge_payload(data, creation=True)
        challenge = cls.challenge_model(**normalized)
        db.session.add(challenge)
        db.session.commit()
        return challenge

    @classmethod
    def update(cls, challenge, request):
        data = request.form or request.get_json()
        normalized = _normalize_challenge_payload(data, creation=False)

        for attr, value in normalized.items():
            setattr(challenge, attr, value)

        return cls.calculate_value(challenge)

    @classmethod
    def solve(cls, user, team, challenge, request):
        BaseChallenge.solve.__func__(cls, user, team, challenge, request)
        return cls.calculate_value(challenge)

    @classmethod
    def attempt(cls, challenge, request):
        global container_manager

        try:
            user, x_id, submitted_flag = get_xid_and_flag()
        except ValueError as err:
            return False, str(err)

        if container_manager is None:
            return False, "Container manager is unavailable."

        container_info = find_active_container(challenge.id, x_id)

        try:
            container_flag = get_container_flag(
                submitted_flag, user, container_manager, container_info, challenge
            )
        except ValueError as err:
            return False, str(err)

        container_flag.used = True
        db.session.commit()

        if container_info:
            container_manager.kill_container(container_info.container_id)
        return True, "Correct"


def load(app: Flask):
    app.db.create_all()
    upgrade(plugin_name="docker_per_team")

    CHALLENGE_CLASSES["container"] = ContainerChallenge
    register_plugin_assets_directory(app, base_path=settings["plugin-info"]["base_path"])

    global container_manager
    container_settings = seed_default_settings()
    container_manager = ContainerManager(container_settings, app)

    base_bp = Blueprint(
        "containers",
        __name__,
        template_folder=settings["blueprint"]["template_folder"],
        static_folder=settings["blueprint"]["static_folder"],
    )

    set_admin_manager(container_manager)
    set_user_manager(container_manager)

    app.register_blueprint(admin_bp)
    app.register_blueprint(containers_bp)
    app.register_blueprint(base_bp)
