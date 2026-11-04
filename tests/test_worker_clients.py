import importlib.util
from pathlib import Path
import sys
import types
import unittest


PACKAGE = "docker_per_team_worker_clients_test"
ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(f"{PACKAGE}.{name}", ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


package = types.ModuleType(PACKAGE)
package.__path__ = [str(ROOT)]
sys.modules[PACKAGE] = package
policy = load("runtime_policy")
pool_module = load("worker_pool")
clients_module = load("worker_clients")


def worker(worker_id):
    identity = policy.RuntimeIdentity.from_environment({
        "CTF_EVENT_ID": "csctf26", "CTF_RELEASE_ID": "release-1", "CTF_TARGET_ID": "staging",
        "CTF_CHALLENGE_NETWORK": f"csctf26_{worker_id}", "CTF_IMAGE_PREFIX": "example.pkg.dev/p/c/",
        "CTF_EGRESS_POLICY": "worker-firewall-default-deny", "CTF_CHALLENGE_BIND_IP": "10.0.0.2",
    })
    return pool_module.WorkerSpec(worker_id, f"ssh://ctfworker@{worker_id}.internal", f"{worker_id}.ctf.example", 800, identity)


class Client:
    def __init__(self): self.closed = False
    def close(self): self.closed = True


class WorkerClientRegistryTests(unittest.TestCase):
    def test_client_is_cached_by_worker_and_unknown_worker_fails_closed(self):
        made = []
        registry = clients_module.WorkerClientRegistry((worker("west-a"), worker("west-b")), lambda spec: made.append(spec.worker_id) or Client())
        first = registry.client("west-a")
        self.assertIs(first, registry.client("west-a"))
        self.assertEqual(made, ["west-a"])
        with self.assertRaises(policy.RuntimePolicyError): registry.client("missing")

    def test_close_all_releases_every_created_client(self):
        registry = clients_module.WorkerClientRegistry((worker("west-a"), worker("west-b")), lambda _spec: Client())
        a, b = registry.client("west-a"), registry.client("west-b")
        registry.close_all()
        self.assertTrue(a.closed and b.closed)
        self.assertEqual(registry.connected_worker_ids(), ())


if __name__ == "__main__": unittest.main()
