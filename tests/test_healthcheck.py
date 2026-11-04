from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "healthcheck.py"
SPEC = importlib.util.spec_from_file_location(
    "docker_per_team_healthcheck",
    MODULE_PATH,
)
healthcheck = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = healthcheck
SPEC.loader.exec_module(healthcheck)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeContainer:
    def __init__(self, states):
        self.states = list(states)
        self.attrs = {"State": {}}
        self.reload_count = 0

    def reload(self):
        self.reload_count += 1
        if self.states:
            self.attrs = {"State": self.states.pop(0)}


def state(status="running", health="starting"):
    return {
        "Status": status,
        "Health": {"Status": health},
    }


class HealthGateTests(unittest.TestCase):
    def test_waits_through_starting_until_healthy(self):
        clock = FakeClock()
        container = FakeContainer(
            [state(), state(), state(health="healthy")]
        )

        healthcheck.wait_until_healthy(
            container,
            10,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(container.reload_count, 3)
        self.assertGreater(clock.now, 0)

    def test_rejects_unhealthy_container(self):
        clock = FakeClock()
        container = FakeContainer([state(health="unhealthy")])

        with self.assertRaisesRegex(
            healthcheck.ContainerHealthError,
            "failed its health check",
        ):
            healthcheck.wait_until_healthy(
                container,
                10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_rejects_container_that_exits_during_startup(self):
        clock = FakeClock()
        container = FakeContainer([state(status="exited")])

        with self.assertRaisesRegex(
            healthcheck.ContainerHealthError,
            "status=exited",
        ):
            healthcheck.wait_until_healthy(
                container,
                10,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

    def test_rejects_startup_timeout(self):
        clock = FakeClock()
        container = FakeContainer([state()])

        with self.assertRaisesRegex(
            healthcheck.ContainerHealthError,
            "startup timeout",
        ):
            healthcheck.wait_until_healthy(
                container,
                1,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )
        self.assertEqual(clock.now, 1.0)


class ViewAssetTests(unittest.TestCase):
    def test_player_sees_health_wait_status_and_accessible_spinner(self):
        asset = (
            Path(__file__).resolve().parents[1] / "assets" / "view.js"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Starting your instance and waiting for its health check",
            asset,
        )
        self.assertIn('alert.setAttribute("aria-live", "polite")', asset)
        self.assertIn('spinner.setAttribute("role", "status")', asset)


if __name__ == "__main__":
    unittest.main()
