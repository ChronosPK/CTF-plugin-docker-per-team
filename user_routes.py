import functools
import threading

from flask import Blueprint, jsonify, request
from CTFd.cache import cache
from .models import ContainerInfoModel
from .container_manager import ContainerException
from .runtime_policy import RuntimePolicyError, account_rate_limit_key
from CTFd.utils.decorators import (
    authed_only,
    admins_only,
    during_ctf_time_only,
    require_verified_emails,
)
from .helpers import *
containers_bp = Blueprint("container_user", __name__, url_prefix="/containers")

container_manager = None
_local_rate_limit_lock = threading.Lock()
_ATOMIC_RATE_LIMIT_SCRIPT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

def set_container_manager(manager):
    global container_manager
    container_manager = manager


def increment_rate_limit(key, interval):
    """Atomically increment a Redis counter; serialize only local fallbacks."""

    backend = cache.cache
    redis_client = getattr(backend, "_write_client", None)
    key_prefix = str(getattr(backend, "key_prefix", "") or "")
    if redis_client is not None:
        return int(
            redis_client.eval(
                _ATOMIC_RATE_LIMIT_SCRIPT,
                1,
                key_prefix + key,
                int(interval),
            )
        )

    # SimpleCache is used only for single-process development. A process-local
    # lock avoids same-worker races without pretending to coordinate workers.
    with _local_rate_limit_lock:
        current = cache.get(key)
        current = int(current or 0) + 1
        cache.set(key, current, timeout=interval)
        return current


def account_ratelimit(method="POST", limit=50, interval=300):
    """Rate-limit one authenticated team/user without coupling shared NATs."""

    def decorator(function):
        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            if request.method == method:
                try:
                    key = account_rate_limit_key(
                        scope_id=get_current_user_or_team(),
                        is_team=is_team_mode(),
                        endpoint=request.endpoint,
                    )
                except (RuntimePolicyError, ValueError) as error:
                    return jsonify({"error": str(error)}), 400

                current = increment_rate_limit(key, interval)
                if int(current) > limit:
                    return (
                        jsonify(
                            {
                                "code": 429,
                                "message": (
                                    f"Too many requests. Limit is {limit} requests "
                                    f"in {interval} seconds"
                                ),
                            }
                        ),
                        429,
                    )
            return function(*args, **kwargs)

        return wrapped

    return decorator


@containers_bp.route("/api/get_connect_type/<int:challenge_id>", methods=["GET"])
@authed_only
@during_ctf_time_only
@require_verified_emails
@account_ratelimit(method="GET", limit=15, interval=60)
def get_connect_type(challenge_id):
    try:
        return connect_type(challenge_id)
    except ContainerException as err:
        return {"error": str(err)}, 500

@containers_bp.route("/api/view_info", methods=["POST"])
@authed_only
@during_ctf_time_only
@require_verified_emails
@account_ratelimit(method="POST", limit=15, interval=60)
def route_view_info():
    try:
        validate_request(request.json, ["chal_id"])
        xid = get_current_user_or_team()
        return view_container_info(container_manager, request.json.get("chal_id"), xid, is_team_mode())
    except ValueError as err:
        return {"error": str(err)}, 400

@containers_bp.route("/api/request", methods=["POST"])
@authed_only
@during_ctf_time_only
@require_verified_emails
@account_ratelimit(method="POST", limit=6, interval=60)
def route_request_container():
    try:
        validate_request(request.json, ["chal_id"])
        xid = get_current_user_or_team()
        return create_container(container_manager, request.json.get("chal_id"), xid, is_team_mode())
    except ValueError as err:
        return {"error": str(err)}, 400

@containers_bp.route("/api/renew", methods=["POST"])
@authed_only
@during_ctf_time_only
@require_verified_emails
@account_ratelimit(method="POST", limit=6, interval=60)
def route_renew_container():
    try:
        validate_request(request.json, ["chal_id"])
        xid = get_current_user_or_team()
        return renew_container(container_manager, request.json.get("chal_id"), xid, is_team_mode())
    except ValueError as err:
        return {"error": str(err)}, 400

@containers_bp.route("/api/stop", methods=["POST"])
@authed_only
@during_ctf_time_only
@require_verified_emails
@account_ratelimit(method="POST", limit=10, interval=60)
def route_stop_container():
    try:
        validate_request(request.json, ["chal_id"])
        xid = get_current_user_or_team()
        running_container = ContainerInfoModel.query.filter_by(
            challenge_id=request.json.get("chal_id"),
            team_id=xid if is_team_mode() else None,
            user_id=None if is_team_mode() else xid
        ).first()

        if running_container and running_container.container_id:
            return kill_container(container_manager, running_container.container_id)
        return {"error": "No container found"}, 400
    except ValueError as err:
        return {"error": str(err)}, 400
