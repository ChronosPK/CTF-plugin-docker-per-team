import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest


PACKAGE = "docker_per_team_worker_pool_test"
ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(f"{PACKAGE}.{name}", ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


if PACKAGE not in sys.modules:
    package = types.ModuleType(PACKAGE)
    package.__path__ = [str(ROOT)]
    sys.modules[PACKAGE] = package


policy = _load("runtime_policy")
pool_module = _load("worker_pool")


def identity():
    return policy.RuntimeIdentity.from_environment(
        {
            "CTF_EVENT_ID": "csctf26",
            "CTF_RELEASE_ID": "release-20261104",
            "CTF_TARGET_ID": "staging",
            "CTF_CHALLENGE_NETWORK": "csctf26_challenge_net",
            "CTF_IMAGE_PREFIX": "example.pkg.dev/project/csctf26/",
            "CTF_EGRESS_POLICY": "worker-firewall-default-deny",
            "CTF_CHALLENGE_BIND_IP": "10.26.0.3",
        }
    )


def worker(worker_id, endpoint, network, bind_ip, hostname):
    return {
        "worker_id": worker_id,
        "docker_base_url": endpoint,
        "challenge_network": network,
        "challenge_bind_ip": bind_ip,
        "docker_hostname": hostname,
        "max_active_instances": 800,
    }


class WorkerPoolTests(unittest.TestCase):
    def test_absent_pool_keeps_named_compatibility_worker(self):
        pool = pool_module.load_worker_pool(
            {}, identity(), {"docker_base_url": "ssh://ctfworker@10.26.0.3", "docker_hostname": "ctf.example"}
        )
        self.assertEqual([entry.worker_id for entry in pool], ["primary"])
        self.assertEqual(pool[0].identity.challenge_network, "csctf26_challenge_net")
        self.assertEqual(pool[0].max_active_instances, 800)

    def test_pool_requires_distinct_workers_and_event_networks(self):
        encoded = json.dumps(
            [
                worker("west-a", "ssh://ctfworker@10.26.0.11", "csctf26_west_a", "10.26.0.11", "w1.ctf.example"),
                worker("west-b", "ssh://ctfworker@10.26.0.12", "csctf26_west_b", "10.26.0.12", "w2.ctf.example"),
            ]
        )
        pool = pool_module.load_worker_pool(
            {pool_module.WORKER_POOL_ENV: encoded}, identity(), {}
        )
        self.assertEqual([entry.worker_id for entry in pool], ["west-a", "west-b"])
        self.assertEqual(pool_module.worker_by_id(pool, "west-b").docker_hostname, "w2.ctf.example")

    def test_pool_rejects_duplicate_network_and_unknown_placement(self):
        encoded = json.dumps(
            [
                worker("west-a", "ssh://ctfworker@10.26.0.11", "csctf26_west", "10.26.0.11", "w1.ctf.example"),
                worker("west-b", "ssh://ctfworker@10.26.0.12", "csctf26_west", "10.26.0.12", "w2.ctf.example"),
            ]
        )
        with self.assertRaises(policy.RuntimePolicyError):
            pool_module.load_worker_pool({pool_module.WORKER_POOL_ENV: encoded}, identity(), {})
        one = pool_module.load_worker_pool(
            {}, identity(), {"docker_base_url": "ssh://ctfworker@10.26.0.3"}
        )
        with self.assertRaises(policy.RuntimePolicyError):
            pool_module.worker_by_id(one, "missing")

    def test_explicit_empty_or_non_ssh_production_pool_fails_closed(self):
        with self.assertRaises(policy.RuntimePolicyError):
            pool_module.load_worker_pool({pool_module.WORKER_POOL_ENV: "[]"}, identity(), {})
        invalid = json.dumps(
            [worker("west-a", "tcp://10.26.0.11:2375", "csctf26_west", "10.26.0.11", "w1.ctf.example")]
        )
        with self.assertRaises(policy.RuntimePolicyError):
            pool_module.load_worker_pool({pool_module.WORKER_POOL_ENV: invalid}, identity(), {})


if __name__ == "__main__":
    unittest.main()
