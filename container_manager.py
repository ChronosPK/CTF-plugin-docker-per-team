import atexit
import json
import os
import secrets
import string
import time

from flask import Flask
from apscheduler.schedulers import SchedulerNotRunningError
from apscheduler.schedulers.background import BackgroundScheduler
import docker
import paramiko.ssh_exception
import requests
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from CTFd.models import db, Flags
from .healthcheck import ContainerHealthError, wait_until_healthy
from .helpers import (
    cleanup_container_records,
    parse_capabilities_value,
)
from .models import ContainerFlagModel, ContainerInfoModel
from .runtime_policy import (
    RuntimeIdentity,
    RuntimePolicyError,
    allow_limited_local_daemon,
    build_hardening_profile,
    get_start_timeout_seconds,
    public_runtime_fingerprint,
    validate_challenge_network_attributes,
    validate_daemon_capabilities,
    validate_docker_endpoint,
    validate_image_reference,
)


def generate_random_flag(challenge):
    """Generate a random flag with the given length and format"""
    flag_length = challenge.random_flag_length
    random_part = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(flag_length)
    )
    return f"{challenge.flag_prefix}{random_part}{challenge.flag_suffix}"


class ContainerException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
        if args:
            self.message = args[0]
        else:
            self.message = None

    def __str__(self) -> str:
        if self.message:
            return self.message
        else:
            return "Unknown Container Exception"


class ContainerManager:
    @staticmethod
    def _get_current_container_id():
        candidates = [os.environ.get("HOSTNAME", "")]

        try:
            with open("/etc/hostname", "r", encoding="utf-8") as hostname_file:
                candidates.append(hostname_file.read().strip())
        except OSError:
            pass

        for candidate in candidates:
            if candidate and all(ch in string.hexdigits for ch in candidate):
                return candidate

        return None

    @classmethod
    def _get_current_container_networks(cls, client):
        container_id = cls._get_current_container_id()
        if not container_id:
            return set()

        try:
            container = client.containers.get(container_id)
        except docker.errors.NotFound:
            return set()

        networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
        return set(networks.keys())

    def _shutdown_expiration_scheduler(self):
        try:
            self.expiration_scheduler.shutdown()
        except (SchedulerNotRunningError, AttributeError):
            pass

    @classmethod
    def validate_settings(cls, settings):
        try:
            identity = RuntimeIdentity.from_environment(os.environ)
            allow_limited_local = allow_limited_local_daemon(
                os.environ,
                identity,
            )
            profile = build_hardening_profile(settings)
            get_start_timeout_seconds(settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

        docker_base_url = (settings.get("docker_base_url") or "").strip()
        try:
            docker_base_url = validate_docker_endpoint(
                docker_base_url,
                identity,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))
        challenge_network = (settings.get("challenge_network") or "").strip()
        if challenge_network != identity.challenge_network:
            raise ContainerException(
                "Challenge network is immutable process configuration and must "
                f"equal CTF_CHALLENGE_NETWORK={identity.challenge_network}"
            )

        try:
            timeout_seconds = int(settings.get("docker_api_timeout", 15))
        except (ValueError, AttributeError, TypeError):
            raise ContainerException("Docker API timeout must be an integer")
        timeout_seconds = min(max(timeout_seconds, 1), 300)

        client = None
        try:
            client = docker.DockerClient(
                base_url=docker_base_url,
                timeout=timeout_seconds,
            )
            client.ping()
            try:
                validate_daemon_capabilities(
                    client.info(),
                    identity=identity,
                    allow_limited_local=allow_limited_local,
                )
            except RuntimePolicyError as err:
                raise ContainerException(str(err))
            try:
                network = client.networks.get(challenge_network)
            except docker.errors.NotFound:
                raise ContainerException(
                    f"Docker network '{challenge_network}' does not exist"
                )
            cls._validate_challenge_network(network, identity)

            current_container_networks = cls._get_current_container_networks(client)
            if challenge_network in current_container_networks:
                raise ContainerException(
                    "Challenge network must be separate from the CTFd application network"
                )
        except docker.errors.DockerException:
            raise ContainerException("CTFd could not connect to Docker")
        except TimeoutError:
            raise ContainerException("CTFd timed out when connecting to Docker")
        except paramiko.ssh_exception.NoValidConnectionsError as err:
            raise ContainerException(
                "CTFd timed out when connecting to Docker: " + str(err)
            )
        except paramiko.ssh_exception.AuthenticationException as err:
            raise ContainerException(
                "CTFd had an authentication error when connecting to Docker: " + str(err)
            )
        finally:
            if client is not None:
                client.close()

    @staticmethod
    def _validate_challenge_network(network, identity):
        try:
            validate_challenge_network_attributes(
                network.attrs or {},
                identity,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

    def __init__(self, settings, app):
        try:
            self.identity = RuntimeIdentity.from_environment(os.environ)
            self.allow_limited_local_daemon = allow_limited_local_daemon(
                os.environ,
                self.identity,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))
        self.settings = dict(settings)
        self.settings["challenge_network"] = self.identity.challenge_network
        try:
            self.hardening_profile = build_hardening_profile(self.settings)
            self.start_timeout_seconds = get_start_timeout_seconds(self.settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err))
        self.client = None
        self.daemon_capabilities = {}
        self.connection_error = None
        self.app = app
        self.expiration_seconds = self._get_expiration_seconds(self.settings)
        self.docker_timeout = self._get_docker_timeout(self.settings)
        docker_base_url = (self.settings.get("docker_base_url") or "").strip()
        try:
            docker_base_url = validate_docker_endpoint(
                docker_base_url,
                self.identity,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

        # Connect to the docker daemon
        try:
            self.initialize_connection(self.settings, app)
        except ContainerException as err:
            self.connection_error = str(err)
            print(f"Docker container service is unavailable: {err}")

    def initialize_connection(self, settings, app) -> None:
        self.settings = dict(settings)
        self.settings["challenge_network"] = self.identity.challenge_network
        self.app = app
        self.expiration_seconds = self._get_expiration_seconds(self.settings)
        self.docker_timeout = self._get_docker_timeout(self.settings)
        try:
            self.hardening_profile = build_hardening_profile(self.settings)
            self.start_timeout_seconds = get_start_timeout_seconds(self.settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

        # Remove any leftover expiration schedulers
        try:
            self.expiration_scheduler.shutdown()
        except (SchedulerNotRunningError, AttributeError):
            # Scheduler was never running
            pass

        docker_base_url = (self.settings.get("docker_base_url") or "").strip()
        try:
            docker_base_url = validate_docker_endpoint(
                docker_base_url,
                self.identity,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

        try:
            self.client = docker.DockerClient(
                base_url=docker_base_url,
                timeout=self.docker_timeout,
            )
            self.client.ping()
            try:
                self.daemon_capabilities = validate_daemon_capabilities(
                    self.client.info(),
                    identity=self.identity,
                    allow_limited_local=self.allow_limited_local_daemon,
                )
            except RuntimePolicyError as err:
                raise ContainerException(str(err))
            challenge_network = self.client.networks.get(
                self.identity.challenge_network
            )
            self._validate_challenge_network(
                challenge_network,
                self.identity,
            )
            if self.identity.challenge_network in self._get_current_container_networks(
                self.client
            ):
                raise ContainerException(
                    "Challenge network must be separate from the CTFd application network"
                )
        except ContainerException as e:
            self._mark_connection_failure(e)
            raise
        except docker.errors.NotFound as e:
            error = ContainerException(
                f"Docker network '{self.identity.challenge_network}' does not exist"
            )
            self._mark_connection_failure(error)
            raise error
        except docker.errors.DockerException as e:
            error = ContainerException("CTFd could not connect to Docker")
            self._mark_connection_failure(error)
            raise error
        except TimeoutError as e:
            error = ContainerException("CTFd timed out when connecting to Docker")
            self._mark_connection_failure(error)
            raise error
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            error = ContainerException(
                "CTFd timed out when connecting to Docker: " + str(e)
            )
            self._mark_connection_failure(error)
            raise error
        except paramiko.ssh_exception.AuthenticationException as e:
            error = ContainerException(
                "CTFd had an authentication error when connecting to Docker: " + str(e)
            )
            self._mark_connection_failure(error)
            raise error

        self.connection_error = None

        EXPIRATION_CHECK_INTERVAL = 5

        if self.expiration_seconds > 0:
            self.expiration_scheduler = BackgroundScheduler()
            self.expiration_scheduler.add_job(
                func=self.kill_expired_containers,
                args=(app,),
                trigger="interval",
                seconds=EXPIRATION_CHECK_INTERVAL,
            )
            self.expiration_scheduler.start()

            # Shut down the scheduler when exiting the app
            atexit.register(self._shutdown_expiration_scheduler)

    def _get_expiration_seconds(self, settings) -> int:
        try:
            expiration_minutes = int(settings.get("container_expiration", 0))
        except (ValueError, AttributeError, TypeError):
            raise ContainerException("Container expiration must be an integer")
        if expiration_minutes <= 0:
            raise ContainerException("Container expiration must be greater than zero")
        return expiration_minutes * 60

    def _get_docker_timeout(self, settings) -> int:
        try:
            timeout_seconds = int(settings.get("docker_api_timeout", 15))
        except (ValueError, AttributeError, TypeError):
            return 15
        return min(max(timeout_seconds, 1), 300)

    def _mark_connection_failure(self, error: Exception) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.client = None
        self.daemon_capabilities = {}
        self.connection_error = str(error)

    def runtime_fingerprint(self) -> dict:
        fingerprint = public_runtime_fingerprint(self.identity, self.settings)
        fingerprint["daemon_capabilities"] = dict(self.daemon_capabilities)
        fingerprint["container_service"] = {
            "connected": self.client is not None,
            "status": "ready" if self.client is not None else "unavailable",
            "local_memory_limit_override": self.allow_limited_local_daemon,
            "error": self.connection_error,
        }
        return fingerprint

    def _validate_live_runtime_boundary(self) -> None:
        try:
            self.daemon_capabilities = validate_daemon_capabilities(
                self.client.info(),
                identity=self.identity,
                allow_limited_local=self.allow_limited_local_daemon,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

        try:
            challenge_network = self.client.networks.get(
                self.identity.challenge_network
            )
        except docker.errors.NotFound:
            raise ContainerException(
                f"Docker network '{self.identity.challenge_network}' does not exist"
            )
        self._validate_challenge_network(challenge_network, self.identity)
        if self.identity.challenge_network in self._get_current_container_networks(
            self.client
        ):
            raise ContainerException(
                "Challenge network must be separate from the CTFd application network"
            )

    def _get_owned_container(self, container_id: str):
        try:
            container = self.client.containers.get(container_id)
        except docker.errors.NotFound:
            return None
        labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
        if not self.identity.owns_labels(labels):
            raise ContainerException(
                "Refusing to operate on a container owned by another or an "
                "unlabelled event"
            )
        return container

    def _validate_image_contract(self, challenge) -> str:
        try:
            image_reference = validate_image_reference(
                challenge.image,
                self.identity,
            )
        except RuntimePolicyError as err:
            raise ContainerException(str(err))

        try:
            image = self.client.images.get(image_reference)
        except docker.errors.ImageNotFound:
            raise ContainerException("Docker image not found")

        config = image.attrs.get("Config", {}) or {}
        configured_user = str(config.get("User", "") or "").strip().lower()
        user_name = configured_user.split(":", 1)[0]
        if not user_name or user_name in {"0", "root"}:
            raise ContainerException(
                "Challenge image must declare a non-root USER"
            )

        healthcheck = config.get("Healthcheck") or {}
        health_test = healthcheck.get("Test") or []
        if not health_test or health_test == ["NONE"]:
            raise ContainerException(
                "Challenge image must declare a Docker HEALTHCHECK"
            )

        expected_port = f"{int(challenge.port)}/tcp"
        exposed_ports = config.get("ExposedPorts") or {}
        if expected_port not in exposed_ports:
            raise ContainerException(
                f"Challenge image does not EXPOSE {expected_port}"
            )
        return image_reference

    def _wait_until_healthy(self, container) -> None:
        try:
            wait_until_healthy(container, self.start_timeout_seconds)
        except ContainerHealthError as err:
            raise ContainerException(str(err)) from err

    def _generate_unique_random_flag(self, challenge) -> str:
        for _ in range(10):
            flag = generate_random_flag(challenge)
            existing_flag = ContainerFlagModel.query.filter_by(
                challenge_id=challenge.id,
                flag=flag,
            ).first()
            if not existing_flag:
                return flag
        raise ContainerException("Could not allocate a unique random flag")

    def _with_advisory_lock(self, name, func):
        engine = db.engine
        dialect_name = getattr(getattr(engine, "dialect", None), "name", "")
        if dialect_name not in {"mysql", "mariadb"}:
            return func()

        connection = engine.connect()

        try:
            acquired = connection.execute(
                text("SELECT GET_LOCK(:name, :timeout)"),
                {"name": name, "timeout": 0},
            ).scalar()
            if acquired != 1:
                return None
            return func()
        finally:
            try:
                connection.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": name})
            finally:
                connection.close()

    def run_command(func):
        def wrapper_run_command(self, *args, **kwargs):
            if self.client is None:
                try:
                    self.initialize_connection(self.settings, self.app)
                except Exception:
                    raise ContainerException("Docker is not connected")
            try:
                if self.client is None:
                    raise ContainerException("Docker is not connected")
                if self.client.ping():
                    return func(self, *args, **kwargs)
                raise ContainerException("Docker is not connected")
            except (
                paramiko.ssh_exception.SSHException,
                ConnectionError,
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                docker.errors.DockerException,
            ) as e:
                # Try to reconnect before failing
                try:
                    self.initialize_connection(self.settings, self.app)
                except Exception:
                    pass
                raise ContainerException(
                    "Docker connection was lost. Please try your request again later."
                )

        return wrapper_run_command

    @run_command
    def kill_expired_containers(self, app: Flask):
        with app.app_context():
            def _cleanup():
                now = int(time.time())
                containers: "list[ContainerInfoModel]" = ContainerInfoModel.query.filter(
                    ContainerInfoModel.expires <= now
                ).all()

                for container in containers:
                    try:
                        self.kill_container(container.container_id)
                    except ContainerException:
                        print(
                            "[Container Expiry Job] Docker is not initialized. Please check your settings."
                        )

            self._with_advisory_lock("docker-per-team:expire-scan", _cleanup)

    @run_command
    def is_container_running(self, container_id: str) -> bool:
        container = self._get_owned_container(container_id)
        if container is None:
            return False
        return container.status == "running"

    @run_command
    def get_running_container_ids(self) -> "set[str]":
        containers = self.client.containers.list(
            filters={
                "label": [
                    "ctfd.plugin=docker_per_team",
                    f"ctfd.event_id={self.identity.event_id}",
                    f"ctfd.target_id={self.identity.target_id}",
                ],
                "status": "running",
            }
        )
        return {container.id for container in containers}

    @run_command
    def create_container(self, challenge, xid, is_team):
        # Recheck the daemon and event network immediately before every launch.
        # A network can be deleted/recreated while CTFd remains up.
        self._validate_live_runtime_boundary()
        kwargs = dict(self.hardening_profile)
        log_config = kwargs.pop("log_config")
        kwargs["log_config"] = docker.types.LogConfig(
            type=log_config["type"],
            config=log_config["config"],
        )
        challenge_network = (self.settings.get("challenge_network") or "").strip()
        if challenge_network != self.identity.challenge_network:
            raise ContainerException("Challenge network identity changed at runtime")
        kwargs["network"] = challenge_network
        image_reference = self._validate_image_contract(challenge)

        if challenge.flag_mode == "random":
            flag = self._generate_unique_random_flag(challenge)
        else:
            # Get flag from flags table
            flag_obj = Flags.query.filter_by(challenge_id=challenge.id).first()
            if flag_obj:
                flag = challenge.flag_prefix + flag_obj.content + challenge.flag_suffix
            else:
                flag = challenge.flag_prefix + challenge.flag_suffix

        volumes = challenge.volumes
        if volumes is not None and volumes != "":
            if self.settings.get("allow_challenge_volumes", "disabled") != "enabled":
                raise ContainerException(
                    "Challenge volume mounts are disabled by plugin settings"
                )
            try:
                volumes_dict = json.loads(volumes)
                for volume in volumes_dict.values():
                    if not isinstance(volume, dict):
                        raise ContainerException(
                            "Every volume mapping must be an object"
                        )
                    bind_path = str(volume.get("bind", "") or "").rstrip("/")
                    mode = str(volume.get("mode", "") or "").lower()
                    if bind_path == "/tmp" or bind_path.startswith("/tmp/"):
                        raise ContainerException(
                            "Challenge volumes may not replace the managed /tmp tmpfs"
                        )
                    if mode != "ro":
                        raise ContainerException(
                            "Challenge volumes must be mounted read-only"
                        )
                kwargs["volumes"] = volumes_dict
            except json.decoder.JSONDecodeError:
                raise ContainerException("Volumes JSON string is invalid")

        capabilities = (challenge.capabilities or "").strip()
        if capabilities:
            try:
                requested_capabilities = set(
                    parse_capabilities_value(capabilities)
                )
                allowed_capabilities = set(
                    parse_capabilities_value(
                        self.settings.get("allowed_capabilities", "")
                    )
                )
            except ValueError as err:
                raise ContainerException(str(err))
            disallowed_capabilities = sorted(
                requested_capabilities - allowed_capabilities
            )
            if disallowed_capabilities:
                raise ContainerException(
                    "Capabilities are not allowed by plugin settings: "
                    + ", ".join(disallowed_capabilities)
                )
            kwargs["cap_add"] = sorted(requested_capabilities)
        if "cap_add" in kwargs:
            kwargs["cap_add"] = sorted(set(kwargs["cap_add"]))

        labels = {
            "ctfd.plugin": "docker_per_team",
            "ctfd.challenge_id": str(challenge.id),
            "ctfd.scope": "team" if is_team else "user",
            "ctfd.scope_id": str(xid),
            **self.identity.labels(),
        }

        container = None
        try:
            container = self.client.containers.run(
                image_reference,
                ports={
                    f"{int(challenge.port)}/tcp": (
                        self.identity.challenge_bind_ip,
                        None,
                    )
                },
                command=challenge.command,
                detach=True,
                auto_remove=True,
                environment={"FLAG": flag},
                labels=labels,
                **kwargs,
            )

            self._wait_until_healthy(container)
            port = self.get_container_port(container.id)
            if port is None:
                raise ContainerException("Could not get container port")
            timestamp = int(time.time())
            expires = timestamp + self.expiration_seconds

            new_container_entry = ContainerInfoModel(
                container_id=container.id,
                challenge_id=challenge.id,
                team_id=xid if is_team else None,
                user_id=None if is_team else xid,
                port=port,
                hostname=None,
                flag=flag,
                timestamp=timestamp,
                expires=expires,
            )
            new_flag_entry = ContainerFlagModel(
                challenge_id=challenge.id,
                container_id=container.id,
                flag=flag,
                team_id=xid if is_team else None,
                user_id=None if is_team else xid,
            )

            db.session.add(new_container_entry)
            db.session.add(new_flag_entry)
            db.session.commit()

            return {
                "container": container,
                "expires": expires,
                "port": port,
            }
        except IntegrityError:
            db.session.rollback()
            try:
                self.client.containers.get(container.id).kill()
            except Exception:
                pass
            raise ContainerException(
                "Another request already created a container for this challenge. Please retry."
            )
        except docker.errors.ImageNotFound:
            db.session.rollback()
            raise ContainerException("Docker image not found")
        except docker.errors.APIError as err:
            db.session.rollback()
            if container is not None:
                try:
                    self.client.containers.get(container.id).kill()
                except Exception:
                    pass
            raise ContainerException(f"Docker API error: {err.explanation}")
        except ContainerException:
            db.session.rollback()
            if container is not None:
                try:
                    self.client.containers.get(container.id).kill()
                except Exception:
                    pass
            raise

    @run_command
    def get_container_port(self, container_id: str) -> "str|None":
        try:
            container = self._get_owned_container(container_id)
            if container is None:
                return None
            for port in list(container.ports.values()):
                if port is not None:
                    return port[0]["HostPort"]
        except (KeyError, IndexError):
            return None

    @run_command
    def get_images(self) -> "list[str]|None":
        try:
            images = self.client.images.list()
        except (KeyError, IndexError):
            return []

        images_list = set()
        for image in images:
            references = list(image.tags or []) + list(
                image.attrs.get("RepoDigests", []) or []
            )
            for reference in references:
                try:
                    validate_image_reference(reference, self.identity)
                except RuntimePolicyError:
                    continue
                images_list.add(reference)

        return sorted(images_list)

    @run_command
    def kill_container(self, container_id: str):
        container_info = ContainerInfoModel.query.filter_by(
            container_id=container_id
        ).first()

        try:
            container = self._get_owned_container(container_id)
            if container is not None:
                container.kill()
        except docker.errors.APIError as err:
            raise ContainerException(f"Docker API error: {err.explanation}")

        if container_info:
            cleanup_container_records(container_info)

    def is_connected(self) -> bool:
        try:
            self.client.ping()
            challenge_network = (self.settings.get("challenge_network") or "").strip()
            if challenge_network != self.identity.challenge_network:
                return False
            self._validate_live_runtime_boundary()
        except Exception:
            return False
        return True
