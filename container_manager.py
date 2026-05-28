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
from .helpers import (
    cleanup_container_records,
)
from .models import ContainerFlagModel, ContainerInfoModel


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
        docker_base_url = (settings.get("docker_base_url") or "").strip()
        if not docker_base_url:
            return
        challenge_network = (settings.get("challenge_network") or "").strip()
        if not challenge_network:
            raise ContainerException("Challenge network must be configured")

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
                client.networks.get(challenge_network)
            except docker.errors.NotFound:
                raise ContainerException(
                    f"Docker network '{challenge_network}' does not exist"
                )

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

    def __init__(self, settings, app):
        self.settings = settings
        self.client = None
        self.app = app
        self.expiration_seconds = self._get_expiration_seconds(settings)
        self.docker_timeout = self._get_docker_timeout(settings)
        docker_base_url = (settings.get("docker_base_url") or "").strip()
        if not docker_base_url:
            return

        # Connect to the docker daemon
        try:
            self.initialize_connection(settings, app)
        except ContainerException:
            print("Docker could not initialize or connect.")
            return

    def initialize_connection(self, settings, app) -> None:
        self.settings = settings
        self.app = app
        self.expiration_seconds = self._get_expiration_seconds(settings)
        self.docker_timeout = self._get_docker_timeout(settings)

        # Remove any leftover expiration schedulers
        try:
            self.expiration_scheduler.shutdown()
        except (SchedulerNotRunningError, AttributeError):
            # Scheduler was never running
            pass

        docker_base_url = (settings.get("docker_base_url") or "").strip()
        if not docker_base_url:
            self.client = None
            return

        try:
            self.client = docker.DockerClient(
                base_url=docker_base_url,
                timeout=self.docker_timeout,
            )
        except docker.errors.DockerException as e:
            self.client = None
            raise ContainerException("CTFd could not connect to Docker")
        except TimeoutError as e:
            self.client = None
            raise ContainerException("CTFd timed out when connecting to Docker")
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            self.client = None
            raise ContainerException(
                "CTFd timed out when connecting to Docker: " + str(e)
            )
        except paramiko.ssh_exception.AuthenticationException as e:
            self.client = None
            raise ContainerException(
                "CTFd had an authentication error when connecting to Docker: " + str(e)
            )

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
            return 0
        return max(expiration_minutes, 0) * 60

    def _get_docker_timeout(self, settings) -> int:
        try:
            timeout_seconds = int(settings.get("docker_api_timeout", 15))
        except (ValueError, AttributeError, TypeError):
            return 15
        return min(max(timeout_seconds, 1), 300)

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

    # TODO: Fix this cause it doesn't work
    def run_command(func):
        def wrapper_run_command(self, *args, **kwargs):
            if self.client is None:
                try:
                    self.initialize_connection(self.settings, self.app)
                except:
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
                except:
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
        container = self.client.containers.list(filters={"id": container_id})
        if len(container) == 0:
            return False
        return container[0].status == "running"

    @run_command
    def get_running_container_ids(self) -> "set[str]":
        containers = self.client.containers.list(
            filters={"label": "ctfd.plugin=docker_per_team", "status": "running"}
        )
        return {container.id for container in containers}

    @run_command
    def create_container(self, challenge, xid, is_team):
        kwargs = {}
        challenge_network = (self.settings.get("challenge_network") or "").strip()
        if not challenge_network:
            raise ContainerException("Challenge network is not configured")
        kwargs["network"] = challenge_network

        if challenge.flag_mode == "random":
            flag = self._generate_unique_random_flag(challenge)
        else:
            # Get flag from flags table
            flag_obj = Flags.query.filter_by(challenge_id=challenge.id).first()
            if flag_obj:
                flag = challenge.flag_prefix + flag_obj.content + challenge.flag_suffix
            else:
                flag = challenge.flag_prefix + challenge.flag_suffix

        # Set the memory and CPU limits for the container
        if self.settings.get("container_maxmemory"):
            try:
                mem_limit = int(self.settings.get("container_maxmemory"))
                if mem_limit > 0:
                    kwargs["mem_limit"] = f"{mem_limit}m"
            except ValueError:
                raise ContainerException(
                    "Configured container memory limit must be an integer"
                )
        if self.settings.get("container_maxcpu"):
            try:
                cpu_period = float(self.settings.get("container_maxcpu"))
                if cpu_period > 0:
                    kwargs["cpu_quota"] = int(cpu_period * 100000)
                    kwargs["cpu_period"] = 100000
            except ValueError:
                raise ContainerException("Configured container CPU limit must be a number")

        volumes = challenge.volumes
        if volumes is not None and volumes != "":
            try:
                volumes_dict = json.loads(volumes)
                kwargs["volumes"] = volumes_dict
            except json.decoder.JSONDecodeError:
                raise ContainerException("Volumes JSON string is invalid")

        capabilities = (challenge.capabilities or "").strip()
        if capabilities:
            try:
                if capabilities.startswith("["):
                    parsed_capabilities = json.loads(capabilities)
                    if not isinstance(parsed_capabilities, list):
                        raise ContainerException(
                            "Capabilities JSON must be an array of capability names"
                        )
                    kwargs["cap_add"] = [
                        str(cap).strip() for cap in parsed_capabilities if str(cap).strip()
                    ]
                else:
                    kwargs["cap_add"] = [
                        cap.strip() for cap in capabilities.split(",") if cap.strip()
                    ]
            except json.decoder.JSONDecodeError:
                raise ContainerException("Capabilities JSON string is invalid")
        if "cap_add" in kwargs:
            kwargs["cap_add"] = sorted(set(kwargs["cap_add"]))

        labels = {
            "ctfd.plugin": "docker_per_team",
            "ctfd.challenge_id": str(challenge.id),
            "ctfd.scope": "team" if is_team else "user",
            "ctfd.scope_id": str(xid),
        }

        container = None
        try:
            timestamp = int(time.time())
            container = self.client.containers.run(
                challenge.image,
                ports={str(challenge.port): None},
                command=challenge.command,
                detach=True,
                auto_remove=True,
                environment={"FLAG": flag},
                labels=labels,
                **kwargs,
            )

            port = self.get_container_port(container.id)
            if port is None:
                raise ContainerException("Could not get container port")
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
            for port in list(self.client.containers.get(container_id).ports.values()):
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

        images_list = []
        for image in images:
            if len(image.tags) > 0:
                images_list.append(image.tags[0])

        images_list.sort()
        return images_list

    @run_command
    def kill_container(self, container_id: str):
        container_info = ContainerInfoModel.query.filter_by(
            container_id=container_id
        ).first()

        try:
            self.client.containers.get(container_id).kill()
        except docker.errors.NotFound:
            pass
        except docker.errors.APIError as err:
            raise ContainerException(f"Docker API error: {err.explanation}")

        if container_info:
            cleanup_container_records(container_info)

    def is_connected(self) -> bool:
        try:
            self.client.ping()
            challenge_network = (self.settings.get("challenge_network") or "").strip()
            if not challenge_network:
                return False
            self.client.networks.get(challenge_network)
        except Exception:
            return False
        return True
