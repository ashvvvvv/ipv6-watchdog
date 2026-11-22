#!/usr/bin/env python3
"""Unit tests for ipv6-watchdog decision pipeline (zero external dependencies)."""

import json
import tempfile
import unittest
from pathlib import Path

import watchdog as wd_mod


class FakeWatchdog(wd_mod.Watchdog):
    """Deterministic test double that records all OS/DNS/Alert actions."""

    def __init__(self, cfg, base_dir, **kwargs):
        super().__init__(cfg, base_dir=base_dir, **kwargs)
        self.bound = []
        self.removed = []
        self.scheduled_removed = []
        self.cf_updates = []
        self.alerts = []
        self.slept = []
        self._now = 1_700_000_000
        self.gp_responses = []
        self.rev_responses = []
        self.local_heal_result = (True, [])

    def now(self):
        return self._now

    def sleep(self, seconds):
        self.slept.append(seconds)

    def bind_v6(self, ip6):
        self.bound.append(ip6)

    def remove_v6(self, ip6):
        self.removed.append(ip6)

    def schedule_remove_v6(self, ip6, delay_sec):
        self.scheduled_removed.append((ip6, delay_sec))

    def warmup_ndp(self, ip6):
        pass

    def local_self_heal(self, current_ip):
        return self.local_heal_result

    def globalping_probe_cn(self, target_ip):
        assert self.gp_responses, f"Unexpected globalping_probe_cn({target_ip})"
        return self.gp_responses.pop(0)

    def reverse_probe_cn(self, src_ip):
        assert self.rev_responses, f"Unexpected reverse_probe_cn({src_ip})"
        return self.rev_responses.pop(0)

    def update_cf_aaaa(self, new_ip):
        self.cf_updates.append(new_ip)
        return {"name": self.cfg["DOMAIN"], "content": new_ip, "ttl": 60}

    def send_alert(self, title, body):
        self.alerts.append((title, body))


def mk_res(passed, failed, ok=True, error=None):
    return {
        "ok": ok,
        "finished": len(passed) + len(failed),
        "passed_carriers": set(passed),
        "failed_carriers": set(failed),
        "details": [f"{c}:3/3" for c in passed] + [f"{c}:0/3" for c in failed],
        "error": error,
    }


class TestWatchdogPipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.cfg = {
            "CF_TOKEN": "example_token",
            "CF_ZONE_ID": "example_zone",
            "CF_RECORD_ID": "example_record",
            "DOMAIN": "edge.example.com",
            "PREFIX64": "2001:db8:abcd:1234",
            "PRESERVE_IPV6": "2001:db8:abcd:1234::2",
            "IFACE": "eth0",
            "PROXY_PORT": "443",
            "FAIL_CARRIER_THRESHOLD": "2",
            "RECHECK_DELAY_SECONDS": "10",
            "COOLDOWN_SECONDS": "1800",
            "MAX_SWITCHES_24H": "3",
            "OLD_IP_GRACE_SECONDS": "120",
        }
        self.initial_ip = "2001:db8:abcd:1234:1111:2222:3333:4444"
        wd_mod.save_state(
            self.base / "state.json",
            {
                "current_ipv6": self.initial_ip,
                "last_check_ts": 0,
                "last_status": "initialized",
                "last_check_summary": "",
                "last_switch_ts": 0,
                "switch_history": [],
            },
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_healthy_fast_path(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [mk_res(["telecom", "unicom", "mobile"], [])]
        self.assertEqual(w.check(), "healthy")
        self.assertEqual(w.bound, [])
        self.assertEqual(w.cf_updates, [])

    def test_single_carrier_degraded_holds(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [mk_res(["telecom", "mobile"], ["unicom"])]
        self.assertEqual(w.check(), "healthy")
        self.assertEqual(w.cf_updates, [])

    def test_local_crash_heals_without_rotating_ip(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [mk_res([], ["telecom", "unicom", "mobile"])]
        w.local_heal_result = (True, ["restarted:xray.service"])
        self.assertEqual(w.check(), "local_healed")
        self.assertEqual(w.bound, [])
        self.assertEqual(w.cf_updates, [])

    def test_indiscriminate_or_subnet_outage_does_not_switch(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [
            mk_res([], ["telecom", "unicom", "mobile"]),  # current fails
            mk_res([], ["telecom", "unicom", "mobile"]),  # fresh random successor ALSO fails
        ]
        self.assertEqual(w.check(), "subnet_or_upstream_outage")
        self.assertEqual(len(w.bound), 1)
        self.assertEqual(w.removed, w.bound)  # temp successor cleaned up
        self.assertEqual(w.cf_updates, [])

    def test_transient_blip_recovers_on_10s_recheck(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [
            mk_res(["mobile"], ["telecom", "unicom"]),    # current fails 2 carriers
            mk_res(["telecom", "unicom", "mobile"], []),  # fresh successor passes
            mk_res(["telecom", "unicom", "mobile"], []),  # 10s recheck: current recovered!
        ]
        self.assertEqual(w.check(), "transient_recovered")
        self.assertEqual(w.slept, [10])
        self.assertEqual(w.removed, w.bound)
        self.assertEqual(w.cf_updates, [])

    def test_confirmed_block_switches_to_verified_successor(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [
            mk_res(["mobile"], ["telecom", "unicom"]),    # current fails 2 carriers
            mk_res(["telecom", "unicom", "mobile"], []),  # fresh successor passes
            mk_res([], ["telecom", "unicom", "mobile"]),  # 10s recheck: current STILL blocked
        ]
        self.assertEqual(w.check(), "switched")
        self.assertEqual(w.slept, [10])
        self.assertEqual(len(w.bound), 1)
        new_ip = w.bound[0]
        self.assertEqual(w.cf_updates, [new_ip])
        self.assertEqual(w.scheduled_removed, [(self.initial_ip, 120)])
        st = wd_mod.load_state(self.base / "state.json")
        self.assertEqual(st["current_ipv6"], new_ip)
        self.assertEqual(len(st["switch_history"]), 1)

    def test_cooldown_and_daily_cap_guardrails(self):
        st = wd_mod.load_state(self.base / "state.json")
        st["last_switch_ts"] = 1_700_000_000 - 300  # 5m ago (< 30m cooldown)
        wd_mod.save_state(self.base / "state.json", st)

        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [
            mk_res([], ["telecom", "unicom", "mobile"]),
            mk_res(["telecom", "unicom", "mobile"], []),
            mk_res([], ["telecom", "unicom", "mobile"]),
        ]
        res = w.check()
        self.assertTrue(res.startswith("switch_deferred:cooldown_active"))
        self.assertEqual(w.removed, w.bound)
        self.assertEqual(w.cf_updates, [])

    def test_globalping_unavailable_falls_back_to_reverse_cn(self):
        w = FakeWatchdog(self.cfg, self.base)
        w.gp_responses = [mk_res([], [], ok=False, error="http_429:rate_limit")]
        w.rev_responses = [
            mk_res(["mobile"], ["telecom", "unicom"]),    # current blocked on 2 carriers
            mk_res(["telecom", "unicom", "mobile"], []),  # fresh random successor passes reverse CN
            mk_res([], ["telecom", "unicom", "mobile"]),  # 10s recheck: current still blocked
        ]
        self.assertEqual(w.check(), "switched")
        self.assertEqual(len(w.cf_updates), 1)

    def test_prefix_normalization_and_random_v6_excludes_reserved(self):
        self.assertEqual(wd_mod.normalize_prefix64("2001:db8:abcd:1234::/64"), "2001:db8:abcd:1234")
        ip = wd_mod.generate_random_v6("2001:db8:abcd:1234", {"2001:db8:abcd:1234::2"})
        self.assertTrue(ip.startswith("2001:db8:abcd:1234:"))
        self.assertNotEqual(ip, "2001:db8:abcd:1234::2")


if __name__ == "__main__":
    unittest.main()
