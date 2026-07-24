import hashlib
import json
import os
import time
from contextlib import contextmanager

from flask import has_request_context, jsonify, request
from sqlalchemy import text

from CTFd.models import Flags, Solves, db
from CTFd.utils import get_config
from CTFd.utils.user import get_current_user

from .models import (
    ContainerChallengeModel,
    ContainerCheatLog,
    ContainerFlagModel,
    ContainerInfoModel,
    ContainerSettingsModel,
)


def get_settings_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")


settings = json.load(open(get_settings_path()))
USERS_MODE = settings["modes"]["USERS_MODE"]
TEAMS_MODE = settings["modes"]["TEAMS_MODE"]
DEFAULT_CONTAINER_SETTINGS = settings.get("defaults", {})
RUNTIME_SETTING_ENVIRONMENT = {
    "docker_base_url": "CTF_DOCKER_BASE_URL",
    "docker_hostname": "CTF_DOCKER_PUBLIC_HOSTNAME",
    "challenge_network": "CTF_CHALLENGE_NETWORK",
    "container_maxmemory": "CTF_CONTAINER_MEMORY_MB",
    "container_maxcpu": "CTF_CONTAINER_CPU_LIMIT",
    "max_containers": "CTF_MAX_CONTAINERS_PER_TEAM",
}
SECURE_NONZERO_DEFAULTS = {
    "container_expiration",
    "container_maxmemory",
    "container_maxcpu",
    "container_pids_limit",
    "container_tmpfs_size_mb",
    "container_log_max_files",
    "container_start_timeout_seconds",
    "max_containers",
}


def settings_to_dict(settings_rows):
    merged_settings = DEFAULT_CONTAINER_SETTINGS.copy()
    merged_settings.update({setting.key: setting.value for setting in settings_rows})
    for setting_key, environment_key in RUNTIME_SETTING_ENVIRONMENT.items():
        environment_value = os.environ.get(environment_key, "").strip()
        if environment_value:
            merged_settings[setting_key] = environment_value
    return merged_settings


def seed_default_settings():
    existing_settings = {
        setting.key: setting for setting in ContainerSettingsModel.query.all()
    }
    missing_defaults = []
    updated_insecure_defaults = False

    for key, value in DEFAULT_CONTAINER_SETTINGS.items():
        if key not in existing_settings:
            missing_defaults.append(ContainerSettingsModel(key=key, value=value))
        elif (
            key in SECURE_NONZERO_DEFAULTS
            and str(existing_settings[key].value or "").strip() in {"", "0", "0.0"}
        ):
            # Earlier plugin versions accepted zero as an unlimited/disabled
            # sentinel for several safety controls. Migrate only those known
            # sentinels; preserve every explicit non-zero operator value.
            existing_settings[key].value = value
            updated_insecure_defaults = True

    if missing_defaults or updated_insecure_defaults:
        db.session.add_all(missing_defaults)
        db.session.commit()

    return settings_to_dict(ContainerSettingsModel.query.all())


def is_team_mode():
    return get_config("user_mode") == TEAMS_MODE


def build_connection_payload(container_manager, challenge, port, expires):
    connect = (challenge.connection_type or "tcp").strip().lower()

    configured_hostname = (container_manager.settings.get("docker_hostname", "") or "").strip()
    request_hostname = request.host.split(":", 1)[0] if has_request_context() else ""
    hostname = configured_hostname or request_hostname

    if connect == "tcp":
        endpoint = f"{hostname}:{port}" if hostname else str(port)
    else:
        scheme = "https" if str(port) == "443" else "http"
        endpoint = f"{scheme}://{hostname}:{port}" if hostname else f"{scheme}://:{port}"

    return {
        "hostname": hostname,
        "port": port,
        "connect": connect,
        "expires": expires,
        "endpoint": endpoint,
    }


def solve_exists_for_account(challenge_id, xid):
    field = Solves.team_id if is_team_mode() else Solves.user_id
    return Solves.query.filter(Solves.challenge_id == challenge_id, field == xid).first()


def cleanup_container_records(container_info, commit=True):
    if not container_info:
        return

    attached_flags = ContainerFlagModel.query.filter_by(
        container_id=container_info.container_id
    ).all()

    if container_info.challenge.flag_mode == "static":
        for flag in attached_flags:
            db.session.delete(flag)
    else:
        for flag in attached_flags:
            # Preserve issued random flags after teardown so teams can still
            # submit a recovered flag even if the instance is gone.
            flag.container_id = None

    db.session.delete(container_info)

    if commit:
        db.session.commit()


def prune_stale_account_containers(container_manager, xid, is_team):
    account_containers = ContainerInfoModel.query.filter_by(
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).all()

    active_containers = []
    stale_removed = False

    for container in account_containers:
        if container_manager.is_container_running(container.container_id):
            active_containers.append(container)
        else:
            cleanup_container_records(container, commit=False)
            stale_removed = True

    if stale_removed:
        db.session.commit()

    return active_containers


@contextmanager
def lock_container_request(xid, is_team, timeout=65):
    engine = db.engine
    dialect_name = getattr(getattr(engine, "dialect", None), "name", "")
    if dialect_name not in {"mysql", "mariadb"}:
        yield
        return

    scope = "team" if is_team else "user"
    # Capacity is account-wide, so every launch for the same team/user must
    # share one lock even when requests target different challenges.
    lock_name = f"docker-per-team:{scope}:{xid}:launch"
    connection = engine.connect()

    try:
        acquired = connection.execute(
            text("SELECT GET_LOCK(:name, :timeout)"),
            {"name": lock_name, "timeout": timeout},
        ).scalar()
        if acquired != 1:
            raise ValueError("Could not acquire a deployment lock. Please try again.")
        yield
    finally:
        try:
            connection.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": lock_name})
        finally:
            connection.close()


def kill_container(container_manager, container_id):
    container = ContainerInfoModel.query.filter_by(container_id=container_id).first()
    if not container:
        return jsonify({"error": "Container not found"}), 400

    from .container_manager import ContainerException

    try:
        container_manager.kill_container(container_id)
    except ContainerException:
        return jsonify(
            {"error": "Docker is not initialized. Please check your settings."}
        )

    return jsonify({"success": "Container killed"})


def renew_container(container_manager, chal_id, xid, is_team):
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()
    if challenge is None:
        return jsonify({"error": "Challenge not found"}), 400

    running_container = ContainerInfoModel.query.filter_by(
        challenge_id=challenge.id,
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).first()
    if running_container is None:
        return jsonify({"error": "Container not found, try resetting the container."})

    try:
        if not container_manager.is_container_running(running_container.container_id):
            cleanup_container_records(running_container)
            return jsonify(
                {"error": "Container is no longer running. Please start a new instance."}
            ), 400
    except Exception as err:
        return jsonify({"error": str(err)}), 500

    try:
        running_container.expires = int(
            time.time() + container_manager.expiration_seconds
        )
        db.session.commit()
    except Exception:
        return jsonify({"error": "Database error occurred, please try again."})

    return jsonify(
        {
            "success": "Container renewed",
                **build_connection_payload(
                    container_manager,
                    challenge,
                    running_container.port,
                    running_container.expires,
                ),
            }
        )


def create_container(container_manager, chal_id, xid, is_team):
    lock_timeout = min(
        max(int(getattr(container_manager, "start_timeout_seconds", 60)) + 5, 5),
        300,
    )
    with lock_container_request(xid, is_team, timeout=lock_timeout):
        # Authentication and route setup may already have opened a
        # REPEATABLE READ transaction before this request waited for MySQL's
        # account lock. End that read-only snapshot so the capacity query sees
        # containers committed by the previous lock holder.
        db.session.rollback()

        challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()
        if challenge is None:
            return jsonify({"error": "Challenge not found"}), 400

        if solve_exists_for_account(chal_id, xid):
            return jsonify({"error": "Challenge already solved"}), 400

        try:
            max_containers = int(container_manager.settings.get("max_containers", 3))
        except (TypeError, ValueError):
            return jsonify({"error": "Plugin setting max_containers is invalid."}), 500

        try:
            active_containers = prune_stale_account_containers(
                container_manager, xid, is_team
            )
        except Exception as err:
            return jsonify({"error": str(err)}), 500

        running_container = next(
            (container for container in active_containers if container.challenge_id == challenge.id),
            None,
        )
        container_count = len(active_containers)

        if container_count >= max_containers:
            return (
                jsonify(
                    {
                        "error": (
                            f"Max containers ({max_containers}) reached. Please stop a "
                            "running container before starting a new one."
                        )
                    }
                ),
                400,
            )

        if running_container:
            return jsonify(
                {
                    "status": "already_running",
                    **build_connection_payload(
                        container_manager,
                        challenge,
                        running_container.port,
                        running_container.expires,
                    ),
                }
            )

        try:
            created_container = container_manager.create_container(challenge, xid, is_team)
        except Exception as err:
            return jsonify({"error": str(err)})

    return jsonify(
        {
            "status": "created",
                **build_connection_payload(
                    container_manager,
                    challenge,
                    created_container["port"],
                    created_container["expires"],
                ),
            }
        )


def view_container_info(container_manager, chal_id, xid, is_team):
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()
    if challenge is None:
        return jsonify({"error": "Challenge not found"}), 400

    running_container = ContainerInfoModel.query.filter_by(
        challenge_id=challenge.id,
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).first()

    if running_container:
        try:
            if container_manager.is_container_running(running_container.container_id):
                return jsonify(
                    {
                        "status": "already_running",
                        **build_connection_payload(
                            container_manager,
                            challenge,
                            running_container.port,
                            running_container.expires,
                        ),
                    }
                )
            cleanup_container_records(running_container)
            return jsonify({"status": "Challenge not started"})
        except Exception as err:
            return jsonify({"error": str(err)}), 500
    else:
        return jsonify({"status": "Challenge not started"})


def connect_type(chal_id):
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()
    if challenge is None:
        return jsonify({"error": "Challenge not found"}), 400
    return jsonify({"status": "Ok", "connect": challenge.connection_type})


def get_xid_and_flag():
    user = get_current_user()
    if not user:
        raise ValueError("You must be logged in to attempt this challenge.")

    if is_team_mode():
        if not user.team_id:
            raise ValueError("You must belong to a team to solve this challenge.")
        x_id = user.team_id
    else:
        x_id = user.id

    data = request.get_json() or request.form
    submitted_flag = data.get("submission", "").strip()
    if not submitted_flag:
        raise ValueError("No flag provided.")

    return user, x_id, submitted_flag


def get_active_container(challenge_id, x_id):
    container_info = ContainerInfoModel.query.filter_by(
        challenge_id=challenge_id,
        team_id=x_id if is_team_mode() else None,
        user_id=None if is_team_mode() else x_id,
    ).first()

    if not container_info:
        raise ValueError("No container is currently active for this challenge.")

    return container_info


def find_active_container(challenge_id, x_id):
    return ContainerInfoModel.query.filter_by(
        challenge_id=challenge_id,
        team_id=x_id if is_team_mode() else None,
        user_id=None if is_team_mode() else x_id,
    ).first()


def get_submission_owner_filters(user):
    if is_team_mode():
        return {"team_id": user.team_id, "user_id": None}
    return {"team_id": None, "user_id": user.id}


def get_expected_static_flag(challenge):
    flag_obj = Flags.query.filter_by(challenge_id=challenge.id).first()
    flag_content = flag_obj.content if flag_obj else ""
    return f"{challenge.flag_prefix}{flag_content}{challenge.flag_suffix}"


def get_container_flag(submitted_flag, user, container_manager, container_info, challenge):
    owner_filters = get_submission_owner_filters(user)

    if container_info and submitted_flag == container_info.flag:
        container_flag = ContainerFlagModel.query.filter_by(
            challenge_id=challenge.id,
            container_id=container_info.container_id,
            flag=submitted_flag,
        ).first()
        if not container_flag:
            container_flag = ContainerFlagModel(
                challenge_id=challenge.id,
                container_id=container_info.container_id,
                flag=submitted_flag,
                **owner_filters,
            )
            db.session.add(container_flag)
        return container_flag

    owned_flag = ContainerFlagModel.query.filter_by(
        challenge_id=challenge.id,
        flag=submitted_flag,
        **owner_filters,
    ).first()
    if owned_flag:
        return owned_flag

    if challenge.flag_mode == "static" and submitted_flag == get_expected_static_flag(challenge):
        container_flag = ContainerFlagModel.query.filter_by(
            challenge_id=challenge.id,
            flag=submitted_flag,
            **owner_filters,
        ).first()
        if not container_flag:
            container_flag = ContainerFlagModel(
                challenge_id=challenge.id,
                container_id=container_info.container_id if container_info else None,
                flag=submitted_flag,
                **owner_filters,
            )
            db.session.add(container_flag)
        return container_flag

    container_flag = ContainerFlagModel.query.filter_by(
        challenge_id=challenge.id,
        flag=submitted_flag,
    ).first()

    if is_team_mode():
        if (
            challenge.flag_mode == "random"
            and container_flag
            and container_flag.team_id != user.team_id
        ):
            log_reused_flag_submission(container_flag, user)
    else:
        if (
            challenge.flag_mode == "random"
            and container_flag
            and container_flag.user_id != user.id
        ):
            log_reused_flag_submission(container_flag, user)

    if not container_flag:
        raise ValueError("Incorrect")

    raise ValueError("Incorrect")


def log_reused_flag_submission(container_flag, user):
    """Record review evidence without leaking a flag or auto-punishing either party."""

    if not container_flag:
        raise ValueError("Incorrect")

    flag_fingerprint = (
        "sha256:"
        + hashlib.sha256(container_flag.flag.encode("utf-8")).hexdigest()
    )
    submitter_filters = (
        {
            "second_team_id": user.team_id,
            "second_user_id": None,
        }
        if is_team_mode()
        else {
            "second_team_id": None,
            "second_user_id": user.id,
        }
    )
    existing_log = ContainerCheatLog.query.filter_by(
        reused_flag=flag_fingerprint,
        challenge_id=container_flag.challenge_id,
        original_team_id=container_flag.team_id,
        original_user_id=container_flag.user_id,
        **submitter_filters,
    ).first()

    if not existing_log:
        db.session.add(
            ContainerCheatLog(
                reused_flag=flag_fingerprint,
                challenge_id=container_flag.challenge_id,
                original_team_id=container_flag.team_id,
                original_user_id=container_flag.user_id,
                timestamp=int(time.time()),
                **submitter_filters,
            )
        )
        db.session.commit()

    # A reused flag is evidence requiring organizer review, not proof of which
    # participant disclosed it. Never auto-ban either the owner or submitter.
    raise ValueError("Incorrect")


def get_current_user_or_team():
    user = get_current_user()
    if user is None:
        raise ValueError("User not found")
    if user.team is None and is_team_mode():
        raise ValueError("User not a member of a team")
    return user.team.id if is_team_mode() else user.id


def validate_request(json_data, required_fields):
    if json_data is None:
        raise ValueError("Invalid request")
    for field in required_fields:
        if json_data.get(field) is None:
            raise ValueError(f"No {field} specified")


def parse_capabilities_value(value):
    raw_value = (value or "").strip()
    if not raw_value:
        return []

    if raw_value.startswith("["):
        parsed_value = json.loads(raw_value)
        if not isinstance(parsed_value, list):
            raise ValueError("Capabilities JSON must be an array of strings")
        capability_values = parsed_value
    else:
        capability_values = raw_value.split(",")

    return [str(capability).strip().upper() for capability in capability_values if str(capability).strip()]
