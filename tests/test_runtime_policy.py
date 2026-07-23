from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "runtime_policy.py"
SPEC = importlib.util.spec_from_file_location("docker_per_team_runtime_policy", MODULE_PATH)
runtime_policy = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = runtime_policy
SPEC.loader.exec_module(runtime_policy)


def runtime_environment(**overrides):
    values = {
        "CTF_EVENT_ID": "cybersea26",
        "CTF_RELEASE_ID": "development",
        "CTF_TARGET_ID": "local",
        "CTF_CHALLENGE_NETWORK": "cybersea26_challenge_net",
        "CTF_IMAGE_PREFIX": "cybersea/",
        "CTF_EGRESS_POLICY": "not-enforced",
        "CTF_CHALLENGE_BIND_IP": "127.0.0.1",
    }
    values.update(overrides)
    return values


class RuntimeIdentityTests(unittest.TestCase):
    def test_identity_requires_every_selector(self):
        for field in runtime_policy.REQUIRED_ENVIRONMENT:
            values = runtime_environment()
            values.pop(field)
            with self.subTest(field=field):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.RuntimeIdentity.from_environment(values)

    def test_identity_accepts_event_owned_local_network(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        self.assertEqual(identity.event_id, "cybersea26")
        self.assertEqual(identity.release_id, "development")
        self.assertEqual(identity.target_id, "local")
        self.assertEqual(identity.challenge_network, "cybersea26_challenge_net")
        self.assertEqual(identity.image_prefix, "cybersea/")
        self.assertEqual(identity.egress_policy, "not-enforced")
        self.assertEqual(identity.challenge_bind_ip, "127.0.0.1")

    def test_network_must_be_event_owned(self):
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "namespaced"
        ):
            runtime_policy.RuntimeIdentity.from_environment(
                runtime_environment(
                    CTF_CHALLENGE_NETWORK="csctf26_challenge_net"
                )
            )

    def test_event_network_namespace_normalizes_identifier_punctuation(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment(
                CTF_EVENT_ID="cyber-sea.26",
                CTF_CHALLENGE_NETWORK="cyber_sea_26_challenge_net",
            )
        )
        self.assertEqual(
            identity.challenge_network,
            "cyber_sea_26_challenge_net",
        )

    def test_production_rejects_development_release(self):
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "immutable release"
        ):
            runtime_policy.RuntimeIdentity.from_environment(
                runtime_environment(CTF_TARGET_ID="production")
            )

    def test_labels_include_event_release_and_target(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        self.assertEqual(
            identity.labels(),
            {
                "ctfd.event_id": "cybersea26",
                "ctfd.release_id": "development",
                "ctfd.target_id": "local",
                "ctfd.egress_policy": "not-enforced",
                "ctfd.challenge_bind_ip": "127.0.0.1",
            },
        )
        self.assertTrue(identity.owns_labels(identity.labels()))
        self.assertFalse(
            identity.owns_labels({"ctfd.event_id": "csctf26"})
        )
        self.assertFalse(
            identity.owns_labels(
                {
                    "ctfd.event_id": "cybersea26",
                    "ctfd.target_id": "production",
                }
            )
        )

    def test_staging_and_production_require_verified_worker_egress_policy(self):
        for target_id in ("staging", "production"):
            with self.subTest(target_id=target_id):
                with self.assertRaisesRegex(
                    runtime_policy.RuntimePolicyError, "default-deny"
                ):
                    runtime_policy.RuntimeIdentity.from_environment(
                        runtime_environment(
                            CTF_TARGET_ID=target_id,
                            CTF_RELEASE_ID="cybersea26-r1",
                        )
                    )

    def test_bind_address_must_be_a_literal_ipv4_address(self):
        for value in ("localhost", "0.0.0.0/0", "::"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    runtime_policy.RuntimePolicyError,
                    "CTF_CHALLENGE_BIND_IP",
                ):
                    runtime_policy.RuntimeIdentity.from_environment(
                        runtime_environment(CTF_CHALLENGE_BIND_IP=value)
                    )


class ImageReferenceTests(unittest.TestCase):
    def test_local_accepts_version_tag(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        self.assertEqual(
            runtime_policy.validate_image_reference(
                "cybersea/harbourmaster:development", identity
            ),
            "cybersea/harbourmaster:development",
        )

    def test_stray_compose_quoting_is_rejected(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "stray quoting"
        ):
            runtime_policy.validate_image_reference(
                '\\"cybersea/pressure-lock:latest"', identity
            )

    def test_cross_event_image_namespace_is_rejected(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "CTF_IMAGE_PREFIX"
        ):
            runtime_policy.validate_image_reference(
                "csctf26/rogue-update:development", identity
            )

    def test_production_requires_sha256_digest(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment(
                CTF_TARGET_ID="production",
                CTF_RELEASE_ID="cybersea26-r1",
                CTF_EGRESS_POLICY="worker-firewall-default-deny",
            )
        )
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "@sha256"
        ):
            runtime_policy.validate_image_reference(
                "cybersea/rogue-update:cybersea26-r1", identity
            )
        digest = "a" * 64
        self.assertEqual(
            runtime_policy.validate_image_reference(
                f"cybersea/rogue-update@sha256:{digest}", identity
            ),
            f"cybersea/rogue-update@sha256:{digest}",
        )


class DockerEndpointTests(unittest.TestCase):
    def test_local_accepts_the_managed_socket(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        self.assertEqual(
            runtime_policy.validate_docker_endpoint(
                "unix:///var/run/docker.sock",
                identity,
            ),
            "unix:///var/run/docker.sock",
        )

    def test_cloud_requires_authenticated_ssh_worker(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment(
                CTF_TARGET_ID="staging",
                CTF_RELEASE_ID="cybersea26-r1",
                CTF_EGRESS_POLICY="worker-firewall-default-deny",
            )
        )
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError,
            "ssh://",
        ):
            runtime_policy.validate_docker_endpoint(
                "tcp://10.0.0.8:2375",
                identity,
            )
        self.assertEqual(
            runtime_policy.validate_docker_endpoint(
                "ssh://ctfworker@10.0.0.8",
                identity,
            ),
            "ssh://ctfworker@10.0.0.8",
        )

    def test_ssh_endpoint_rejects_embedded_password_or_path(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment(
                CTF_TARGET_ID="production",
                CTF_RELEASE_ID="cybersea26-r1",
                CTF_EGRESS_POLICY="worker-firewall-default-deny",
            )
        )
        for endpoint in (
            "ssh://worker:secret@10.0.0.8",
            "ssh://worker@10.0.0.8/path",
            "ssh://10.0.0.8",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.validate_docker_endpoint(
                        endpoint,
                        identity,
                    )


class ChallengeNetworkTests(unittest.TestCase):
    @staticmethod
    def network_attributes(**overrides):
        values = {
            "Name": "cybersea26_challenge_net",
            "Driver": "bridge",
            "Internal": False,
            "Options": {
                "com.docker.network.bridge.enable_icc": "false",
            },
            "Labels": {
                "ctfd.event_id": "cybersea26",
                "ctfd.network_role": "challenge",
                "ctfd.egress_policy": "not-enforced",
            },
        }
        values.update(overrides)
        return values

    def test_direct_mode_event_network_contract(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        runtime_policy.validate_challenge_network_attributes(
            self.network_attributes(),
            identity,
        )

    def test_internal_network_is_rejected_because_it_cannot_publish_ports(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "non-internal"
        ):
            runtime_policy.validate_challenge_network_attributes(
                self.network_attributes(Internal=True),
                identity,
            )

    def test_network_requires_icc_off_and_matching_event_egress_labels(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        invalid_attributes = (
            self.network_attributes(Driver="overlay"),
            self.network_attributes(Options={}),
            self.network_attributes(
                Labels={
                    "ctfd.event_id": "csctf26",
                    "ctfd.network_role": "challenge",
                    "ctfd.egress_policy": "not-enforced",
                }
            ),
            self.network_attributes(
                Labels={
                    "ctfd.event_id": "cybersea26",
                    "ctfd.network_role": "challenge",
                    "ctfd.egress_policy": "worker-firewall-default-deny",
                }
            ),
        )
        for attrs in invalid_attributes:
            with self.subTest(attrs=attrs):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.validate_challenge_network_attributes(
                        attrs,
                        identity,
                    )


class HardeningProfileTests(unittest.TestCase):
    def test_profile_enforces_all_common_controls(self):
        profile = runtime_policy.build_hardening_profile({})
        self.assertEqual(profile["cap_drop"], ["ALL"])
        self.assertEqual(
            profile["security_opt"], ["no-new-privileges:true"]
        )
        self.assertTrue(profile["read_only"])
        self.assertTrue(profile["init"])
        self.assertEqual(profile["pids_limit"], 512)
        self.assertEqual(profile["mem_limit"], "1024m")
        self.assertEqual(profile["memswap_limit"], "1024m")
        self.assertEqual(profile["cpu_quota"], 100000)
        self.assertIn("noexec", profile["tmpfs"]["/tmp"])
        self.assertEqual(
            profile["log_config"]["config"],
            {"max-size": "10m", "max-file": "3"},
        )

    def test_limits_must_not_be_disabled_with_zero(self):
        for key in (
            "container_maxmemory",
            "container_maxcpu",
            "container_pids_limit",
            "container_tmpfs_size_mb",
            "container_log_max_files",
        ):
            with self.subTest(key=key):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.build_hardening_profile({key: "0"})

    def test_cpu_limit_must_be_finite(self):
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.build_hardening_profile(
                        {"container_maxcpu": value}
                    )

    def test_log_size_is_strictly_validated(self):
        for value in ("", "0m", "10", "10mb", "-1"):
            with self.subTest(value=value):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.build_hardening_profile(
                        {"container_log_max_size": value}
                    )

    def test_public_fingerprint_contains_no_environment_or_secret(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        fingerprint = runtime_policy.public_runtime_fingerprint(identity, {})
        self.assertEqual(fingerprint["event_id"], "cybersea26")
        self.assertEqual(fingerprint["release_id"], "development")
        self.assertEqual(fingerprint["policy"]["max_containers"], 3)
        self.assertNotIn("FLAG", repr(fingerprint))
        self.assertNotIn("token", repr(fingerprint).lower())


class DaemonCapabilityTests(unittest.TestCase):
    def test_daemon_must_enforce_every_promised_limit(self):
        capabilities = runtime_policy.validate_daemon_capabilities(
            {key: True for key in runtime_policy.REQUIRED_DAEMON_CAPABILITIES}
        )
        self.assertTrue(all(capabilities.values()))

    def test_daemon_rejects_discarded_memory_limits(self):
        info = {
            key: True for key in runtime_policy.REQUIRED_DAEMON_CAPABILITIES
        }
        info["MemoryLimit"] = False
        info["SwapLimit"] = False
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "memory limits"
        ):
            runtime_policy.validate_daemon_capabilities(info)

    def test_explicit_local_override_allows_only_missing_memory_controls(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        info = {
            key: True for key in runtime_policy.REQUIRED_DAEMON_CAPABILITIES
        }
        info["MemoryLimit"] = False
        info["SwapLimit"] = False

        capabilities = runtime_policy.validate_daemon_capabilities(
            info,
            identity=identity,
            allow_limited_local=True,
        )
        self.assertFalse(capabilities["MemoryLimit"])
        self.assertFalse(capabilities["SwapLimit"])

        info["PidsLimit"] = False
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "PID limits"
        ):
            runtime_policy.validate_daemon_capabilities(
                info,
                identity=identity,
                allow_limited_local=True,
            )

    def test_local_override_is_rejected_outside_local_target(self):
        for target_id in ("staging", "production"):
            with self.subTest(target_id=target_id):
                identity = runtime_policy.RuntimeIdentity.from_environment(
                    runtime_environment(
                        CTF_TARGET_ID=target_id,
                        CTF_RELEASE_ID="cybersea26-r1",
                        CTF_EGRESS_POLICY="worker-firewall-default-deny",
                    )
                )
                with self.assertRaisesRegex(
                    runtime_policy.RuntimePolicyError, "only for local"
                ):
                    runtime_policy.allow_limited_local_daemon(
                        {
                            runtime_policy.LOCAL_DAEMON_CAPABILITY_OVERRIDE_ENV: "true"
                        },
                        identity,
                    )

    def test_local_override_requires_an_explicit_boolean(self):
        identity = runtime_policy.RuntimeIdentity.from_environment(
            runtime_environment()
        )
        with self.assertRaisesRegex(
            runtime_policy.RuntimePolicyError, "true or false"
        ):
            runtime_policy.allow_limited_local_daemon(
                {
                    runtime_policy.LOCAL_DAEMON_CAPABILITY_OVERRIDE_ENV: "yes"
                },
                identity,
            )


class AccountRateLimitKeyTests(unittest.TestCase):
    def test_team_and_user_keys_are_isolated(self):
        team_key = runtime_policy.account_rate_limit_key(
            scope_id=42,
            is_team=True,
            endpoint="containers.route_request_container",
        )
        user_key = runtime_policy.account_rate_limit_key(
            scope_id=42,
            is_team=False,
            endpoint="containers.route_request_container",
        )
        self.assertEqual(
            team_key,
            "docker-per-team:rate-v2:team:42:containers.route_request_container",
        )
        self.assertNotEqual(team_key, user_key)

    def test_rate_limit_key_rejects_missing_identity(self):
        for scope_id in (None, "", 0, -1):
            with self.subTest(scope_id=scope_id):
                with self.assertRaises(runtime_policy.RuntimePolicyError):
                    runtime_policy.account_rate_limit_key(
                        scope_id=scope_id,
                        is_team=True,
                        endpoint="containers.route_request_container",
                    )


if __name__ == "__main__":
    unittest.main()
