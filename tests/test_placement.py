import importlib.util
from pathlib import Path
import sys
import types
import unittest


PACKAGE = "docker_per_team_placement_test"
ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(f"{PACKAGE}.{name}", ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


package = types.ModuleType(PACKAGE)
package.__path__ = [str(ROOT)]
sys.modules[PACKAGE] = package
policy = _load("runtime_policy")
pool_module = _load("worker_pool")
placement = _load("placement")


def worker(name):
    identity = policy.RuntimeIdentity.from_environment(
        {
            "CTF_EVENT_ID": "csctf26", "CTF_RELEASE_ID": "release-1", "CTF_TARGET_ID": "staging",
            "CTF_CHALLENGE_NETWORK": f"csctf26_{name}", "CTF_IMAGE_PREFIX": "example.pkg.dev/p/c/",
            "CTF_EGRESS_POLICY": "worker-firewall-default-deny", "CTF_CHALLENGE_BIND_IP": "10.0.0.2",
        }
    )
    return pool_module.WorkerSpec(name, f"ssh://ctfworker@{name}.internal", f"{name}.ctf.example", 800, identity)


class PlacementTests(unittest.TestCase):
    def setUp(self):
        self.workers = (worker("west-a"), worker("west-b"))
        self.key = placement.PlacementKey("csctf26", "release-1", "team", 42)

    def test_initial_choice_is_stable_and_restricted_to_eligible_workers(self):
        first = placement.choose_initial_worker(self.key, self.workers, eligible_worker_ids={"west-a", "west-b"})
        again = placement.choose_initial_worker(self.key, self.workers, eligible_worker_ids={"west-a", "west-b"})
        self.assertEqual(first.worker_id, again.worker_id)
        only_b = placement.choose_initial_worker(self.key, self.workers, eligible_worker_ids={"west-b"})
        self.assertEqual(only_b.worker_id, "west-b")

    def test_no_admitted_worker_and_unknown_stored_worker_fail_closed(self):
        with self.assertRaises(policy.RuntimePolicyError):
            placement.choose_initial_worker(self.key, self.workers, eligible_worker_ids=set())
        with self.assertRaises(policy.RuntimePolicyError):
            placement.require_persisted_worker("retired", self.workers)

    def test_scope_validation_rejects_ambiguous_identity(self):
        with self.assertRaises(policy.RuntimePolicyError):
            placement.PlacementKey("csctf26", "release-1", "account", 42).canonical_bytes()
        with self.assertRaises(policy.RuntimePolicyError):
            placement.PlacementKey("csctf26", "release-1", "team", 0).canonical_bytes()


if __name__ == "__main__":
    unittest.main()
