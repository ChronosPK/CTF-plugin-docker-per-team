from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from CTFd.models import db
from .models import ContainerCheatLog, ContainerInfoModel, ContainerSettingsModel
from .container_manager import ContainerException, ContainerManager
from CTFd.utils.decorators import admins_only
from .helpers import *

admin_bp = Blueprint("container_admin", __name__, url_prefix="/containers/admin")

container_manager = None

def set_container_manager(manager):
    global container_manager
    container_manager = manager


def normalize_settings_payload(form):
    base_fields = [
        "docker_base_url",
        "docker_hostname",
        "docker_api_timeout",
        "challenge_network",
        "container_expiration",
        "container_maxmemory",
        "container_maxcpu",
        "max_containers",
    ]
    advanced_fields = [
        "allow_challenge_volumes",
        "allowed_capabilities",
    ]
    defaults = settings_to_dict(ContainerSettingsModel.query.all())

    payload = {}
    for field in base_fields + advanced_fields:
        value = form.get(field)
        if value is None:
            value = defaults.get(field, "")
        payload[field] = str(value).strip()

    required_fields = [
        "docker_base_url",
        "docker_api_timeout",
        "challenge_network",
        "container_expiration",
        "container_maxmemory",
        "container_maxcpu",
        "max_containers",
    ]
    for field in required_fields:
        if payload[field] == "":
            raise ValueError(f"{field} is required.")

    integer_fields = (
        "container_expiration",
        "container_maxmemory",
        "max_containers",
        "docker_api_timeout",
    )
    for field in integer_fields:
        if not payload[field]:
            continue
        try:
            parsed_value = int(payload[field])
        except ValueError:
            raise ValueError(f"{field} must be an integer.")
        if parsed_value < 0:
            raise ValueError(f"{field} must be zero or greater.")

    if payload["docker_api_timeout"] and int(payload["docker_api_timeout"]) < 1:
        raise ValueError("docker_api_timeout must be at least 1 second.")

    if payload["max_containers"] and int(payload["max_containers"]) < 1:
        raise ValueError("max_containers must be at least 1.")

    if payload["container_maxcpu"]:
        try:
            parsed_cpu = float(payload["container_maxcpu"])
        except ValueError:
            raise ValueError("container_maxcpu must be a number.")
        if parsed_cpu < 0:
            raise ValueError("container_maxcpu must be zero or greater.")

    if payload["allow_challenge_volumes"] not in {"disabled", "enabled"}:
        raise ValueError("allow_challenge_volumes must be either disabled or enabled.")

    return payload

# Admin dashboard
@admin_bp.route("/dashboard", methods=["GET"])
@admins_only
def route_containers_dashboard():
    connected = False
    running_ids = set()
    try:
        connected = container_manager.is_connected()
        if connected:
            running_ids = container_manager.get_running_container_ids()
    except ContainerException:
        pass

    running_containers = ContainerInfoModel.query.order_by(
        ContainerInfoModel.timestamp.desc()
    ).all()

    for container in running_containers:
        container.is_running = container.container_id in running_ids

    return render_template(
        "container_dashboard.html",
        containers=running_containers,
        connected=connected,
    )

@admin_bp.route("/settings", methods=["GET"])
@admins_only
def route_containers_settings():
    connected = False
    try:
        connected = container_manager.is_connected()
    except ContainerException:
        pass

    return render_template(
        "container_settings.html",
        settings=container_manager.settings,
        connected=connected,
    )

@admin_bp.route("/cheat", methods=["GET"])
@admins_only
def route_containers_cheat():
    connected = False
    try:
        connected = container_manager.is_connected()
    except ContainerException:
        pass

    cheat_logs = ContainerCheatLog.query.order_by(ContainerCheatLog.timestamp.desc()).all()

    return render_template(
        "container_cheat.html",
        connected=connected,
        cheat_logs=cheat_logs
    )

# Admin API
@admin_bp.route("/api/settings", methods=["POST"])
@admins_only
def route_update_settings():
    try:
        payload = normalize_settings_payload(request.form)
        ContainerManager.validate_settings(payload)
    except ValueError as err:
        flash(str(err), "error")
        return redirect(url_for(".route_containers_settings"))
    except ContainerException as err:
        flash(str(err), "error")
        return redirect(url_for(".route_containers_settings"))

    # Update settings dynamically
    for key, value in payload.items():
        setting = ContainerSettingsModel.query.filter_by(key=key).first()

        if not setting:
            setting = ContainerSettingsModel(key=key, value=value)
            db.session.add(setting)
        else:
            setting.value = value

    db.session.commit()

    # Refresh container manager settings
    container_manager.settings = settings_to_dict(
        ContainerSettingsModel.query.all()
    )

    try:
        container_manager.initialize_connection(
            container_manager.settings, current_app._get_current_object()
        )
    except ContainerException as err:
        flash(str(err), "error")
        return redirect(url_for(".route_containers_settings"))

    return redirect(url_for(".route_containers_dashboard"))

@admin_bp.route("/api/kill", methods=["POST"])
@admins_only
def route_admin_kill_container():
    try:
        validate_request(request.json, ["container_id"])
        return kill_container(container_manager, request.json.get("container_id"))
    except ValueError as err:
        return {"error": str(err)}, 400

@admin_bp.route("/api/purge", methods=["POST"])
@admins_only
def route_purge_containers():
    """Bulk delete multiple containers"""
    try:
        validate_request(request.json, ["container_ids"])
        container_ids = request.json.get("container_ids", [])
        if not container_ids:
            return {"error": "No containers selected"}, 400

        deleted_count = 0
        for container_id in container_ids:
            container = ContainerInfoModel.query.filter_by(container_id=container_id).first()
            if container:
                try:
                    container_manager.kill_container(container_id)
                    deleted_count += 1
                except ContainerException:
                    continue

        return {"success": f"Deleted {deleted_count} container(s)"}
    except ValueError as err:
        return {"error": str(err)}, 400
        
@admin_bp.route("/api/images", methods=["GET"])
@admins_only
def route_get_images():
    try:
        images = container_manager.get_images()
    except ContainerException as err:
        return {"error": str(err)}

    return {"images": images}

@admin_bp.route("/api/running_containers", methods=["GET"])
@admins_only
def route_get_running_containers():
    running_containers = ContainerInfoModel.query.order_by(
        ContainerInfoModel.timestamp.desc()
    ).all()

    connected = False
    running_ids = set()
    try:
        connected = container_manager.is_connected()
        if connected:
            running_ids = container_manager.get_running_container_ids()
    except ContainerException:
        pass

    # Create lists to store unique teams and challenges
    unique_teams = set()
    unique_challenges = set()

    for container in running_containers:
        container.is_running = container.container_id in running_ids

        # Add team and challenge to the unique sets
        if is_team_mode() is True:
            unique_teams.add(f"{container.team.name} [{container.team_id}]")
        else:
            unique_teams.add(f"{container.user.name} [{container.user_id}]")
        unique_challenges.add(
            f"{container.challenge.name} [{container.challenge_id}]"
        )

    # Convert unique sets to lists
    unique_teams_list = list(unique_teams)
    unique_challenges_list = list(unique_challenges)

    # Create a list of dictionaries containing running_containers data
    running_containers_data = []
    for container in running_containers:
        if is_team_mode() is True:
            container_data = {
                "container_id": container.container_id,
                "image": container.challenge.image,
                "challenge": f"{container.challenge.name} [{container.challenge_id}]",
                "team": f"{container.team.name} [{container.team_id}]",
                "port": container.port,
                "created": container.timestamp,
                "expires": container.expires,
                "is_running": container.is_running,
            }
        else:
            container_data = {
                "container_id": container.container_id,
                "image": container.challenge.image,
                "challenge": f"{container.challenge.name} [{container.challenge_id}]",
                "user": f"{container.user.name} [{container.user_id}]",
                "port": container.port,
                "created": container.timestamp,
                "expires": container.expires,
                "is_running": container.is_running,
            }
        running_containers_data.append(container_data)

    # Create a JSON response containing running_containers_data, unique teams, and unique challenges
    response_data = {
        "containers": running_containers_data,
        "connected": connected,
        "teams": unique_teams_list,
        "challenges": unique_challenges_list,
    }

    # Return the JSON response
    return jsonify(response_data)
