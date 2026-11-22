#!/usr/bin/env python3
"""
ipv6-watchdog — High-SLA IPv6 /64 GFW Blocking Detector & Zero-Downtime Auto-Rotator.

Zero third-party dependencies (pure Python 3.8+ standard library).
Designed for dual-stack / pure-IPv6 proxy servers with an on-link or routed /64 subnet
and a Cloudflare-managed AAAA DNS record (TTL 60s, DNS Only).

Decision pipeline (straight-line high-SLA flow):
  1. Primary check: Globalping forward TCP probe to [current_ipv6]:PORT from
     China Telecom (AS4134) + China Unicom (AS4837) + China Mobile probes.
     - >= 2 distinct CN carriers pass -> HEALTHY (done in 1 call, 3 credits).
  2. On >= 2 carriers failing -> triage in strict order:
     a) Local self-heal: verify NIC IPv6, systemd services, local TCP handshake,
        optional nftables IPv4-drop & Xray inbound users. If local was broken,
        repair locally and NEVER blame GFW / rotate IP.
     b) Fresh random successor control: bind a brand-new unused random /64 IPv6,
        warm NDP (2s), and probe [successor_ipv6]:PORT from CN.
        - If successor ALSO fails (< 2 carriers) -> subnet/upstream/probe outage:
          clean up temporary successor, leave DNS untouched, alert.
        - If successor passes (>= 2 carriers) -> single IP/port block proven AND
          the successor is already warmed up & CN-verified!
     c) Fast recheck (default 10s): re-probe [current_ipv6]:PORT from CN.
        - If recovered -> transient blip; remove temp successor, leave DNS untouched.
        - If still blocked -> enforce cooldown & 24h cap, update Cloudflare AAAA
          to the already-verified successor, persist state, and drain old IPv6
          for grace period before deletion (zero proxy restart).
  3. Automatic fallback: if Globalping API is unreachable or rate-limited (429),
     degrades to local reverse 3-carrier 9-endpoint CN IPv6 TCPing using the same
     fresh-random-successor control model.
"""

import argparse
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_BASE_DIR = Path(os.environ.get("IPV6_WATCHDOG_DIR", "/opt/ipv6-watchdog"))

# Verified mainland China public static IPv6 endpoints across Telecom / Unicom / Mobile.
# Used ONLY as automatic fallback when Globalping API is unavailable or rate-limited.
DEFAULT_CN_FALLBACK_PROBES = [
    ("telecom", "240e:688:400:2fa::57", 443, "AS4812_CT_SH"),
    ("telecom", "240e:40:e002:1:a:3ee3:c00:0", 443, "AS4134_CT_BJ"),
    ("telecom", "240e:40:8000::10", 53, "AS4134_CT_DNS"),
    ("unicom", "2408:8000:9000:20e6::5dd", 443, "AS17621_CU_SH"),
    ("unicom", "2408:815f:e000:1:8:6:2:3", 443, "AS4837_CU_HQ"),
    ("unicom", "2408:8663::2", 53, "AS4837_CU_DNS"),
    ("mobile", "2409:8c20:1833:1000::ad5:2cb5", 443, "AS9808_CM_MIRROR"),
    ("mobile", "2409:8c85:202c::aac:222a", 443, "AS9808_CM_CLOUD"),
    ("mobile", "2409:8080::3", 53, "AS9808_CM_DNS"),
]

TELECOM_ASNS = {4134, 4809, 4812, 4816, 4847, 134774, 140061}
UNICOM_ASNS = {4837, 9929, 4808, 17621, 17622, 17623, 17816}
MOBILE_ASNS = {9808, 58453, 56040, 56041, 56042, 56044, 56045, 56046, 56047, 56048, 24400, 24444, 24445}

USER_AGENT = "ipv6-watchdog/2.0 (+https://github.com/ashvvvvv/ipv6-watchdog)"


def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    print(f"[{ts}] {msg}", flush=True)


def parse_env_file(path):
    cfg = {}
    if not path.exists():
        return cfg
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
            v = v[1:-1]
        cfg[k] = v
    return cfg


def parse_csv(val):
    return [item.strip() for item in str(val or "").split(",") if item.strip()]


def load_state(state_file):
    if state_file.exists():
        return json.loads(state_file.read_text(encoding="utf-8"))
    return {
        "current_ipv6": "",
        "last_check_ts": 0,
        "last_status": "initialized",
        "last_check_summary": "",
        "last_switch_ts": 0,
        "switch_history": [],
    }


def save_state(state_file, state):
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_file.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(state_file)


def classify_cn_carrier(asn, network=""):
    try:
        asn_int = int(asn) if asn is not None else 0
    except (TypeError, ValueError):
        asn_int = 0
    net_low = (network or "").lower()
    if asn_int in TELECOM_ASNS or "telecom" in net_low or "chinanet" in net_low:
        return "telecom"
    if asn_int in UNICOM_ASNS or "unicom" in net_low:
        return "unicom"
    if asn_int in MOBILE_ASNS or "mobile" in net_low:
        return "mobile"
    if asn_int > 0:
        return f"as{asn_int}"
    return "other"


def normalize_prefix64(prefix_str):
    """Validate and return the canonical first 4 hextets of a /64 prefix (e.g. '2001:db8:abcd:1234')."""
    s = prefix_str.strip()
    if "/" not in s:
        s = s.rstrip(":") + "::/64"
    net = ipaddress.IPv6Network(s, strict=False)
    if net.prefixlen != 64:
        raise ValueError(f"Expected a /64 IPv6 prefix, got /{net.prefixlen}: {prefix_str}")
    full = net.network_address.exploded.split(":")[:4]
    return ":".join(f"{int(h, 16):x}" for h in full)


def generate_random_v6(prefix64, exclude):
    norm_prefix = normalize_prefix64(prefix64)
    excluded_norm = set()
    for ip in exclude:
        if ip:
            try:
                excluded_norm.add(str(ipaddress.IPv6Address(ip)))
            except ValueError:
                pass
    for _ in range(32):
        parts = [secrets.randbelow(0xFFFF) or 1 for _ in range(4)]
        cand = str(ipaddress.IPv6Address(f"{norm_prefix}:{parts[0]:x}:{parts[1]:x}:{parts[2]:x}:{parts[3]:x}"))
        if cand not in excluded_norm:
            return cand
    raise RuntimeError("Failed to generate unique random IPv6 in /64 prefix")


class Watchdog:
    """Encapsulates external calls (OS, Globalping, Cloudflare, Alerts) for clean testing."""

    def __init__(self, cfg, base_dir=DEFAULT_BASE_DIR, dry_run=False):
        self.cfg = cfg
        self.base_dir = Path(base_dir)
        self.state_file = self.base_dir / "state.json"
        self.dry_run = dry_run

        self.iface = cfg.get("IFACE", "eth0")
        self.prefix64 = cfg.get("PREFIX64", "")
        self.preserve_v6 = {
            str(ipaddress.IPv6Address(ip))
            for ip in parse_csv(cfg.get("PRESERVE_IPV6", ""))
        }
        self.proxy_port = int(cfg.get("PROXY_PORT", "443"))
        self.fail_carrier_threshold = int(cfg.get("FAIL_CARRIER_THRESHOLD", "2"))
        self.recheck_delay = int(cfg.get("RECHECK_DELAY_SECONDS", "10"))
        self.cooldown = int(cfg.get("COOLDOWN_SECONDS", "1800"))
        self.max_switches_24h = int(cfg.get("MAX_SWITCHES_24H", "3"))
        self.old_ip_grace = int(cfg.get("OLD_IP_GRACE_SECONDS", "120"))
        self.ndp_warmup_sec = float(cfg.get("NDP_WARMUP_SECONDS", "2.0"))
        self.monitor_services = parse_csv(cfg.get("MONITOR_SERVICES", "xray.service"))
        self.enforce_nft_v4_drop = cfg.get("ENFORCE_NFT_DROP_V4", "0") == "1"
        self.xray_bin = cfg.get("XRAY_BIN", "/usr/local/bin/xray")
        self.xray_api = cfg.get("XRAY_API_ADDR", "")
        self.xray_inbounds = parse_csv(cfg.get("XRAY_INBOUND_TAGS", ""))
        self.xray_sidecar = cfg.get("XRAY_SIDECAR_SERVICE", "")

    # ---------------- OS / Network Primitives ----------------

    def sleep(self, seconds):
        time.sleep(seconds)

    def now(self):
        return int(time.time())

    def run_cmd(self, args, check=False, timeout=15):
        return subprocess.run(args, capture_output=True, text=True, check=check, timeout=timeout)

    def iface_has_v6(self, ip6):
        norm = str(ipaddress.IPv6Address(ip6))
        p = self.run_cmd(["ip", "-6", "-o", "addr", "show", "dev", self.iface])
        for line in p.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet6":
                addr = parts[3].split("/")[0]
                try:
                    if str(ipaddress.IPv6Address(addr)) == norm:
                        return True
                except ValueError:
                    pass
        return False

    def bind_v6(self, ip6):
        if self.dry_run:
            log(f"[DRY-RUN] ip -6 addr replace {ip6}/64 dev {self.iface} preferred_lft 0")
            return
        self.run_cmd(
            ["ip", "-6", "addr", "replace", f"{ip6}/64", "dev", self.iface, "preferred_lft", "0"],
            check=True,
        )

    def remove_v6(self, ip6):
        if not ip6:
            return
        try:
            norm = str(ipaddress.IPv6Address(ip6))
        except ValueError:
            return
        if norm in self.preserve_v6:
            return
        if self.dry_run:
            log(f"[DRY-RUN] ip -6 addr del {norm}/64 dev {self.iface}")
            return
        self.run_cmd(["ip", "-6", "addr", "del", f"{norm}/64", "dev", self.iface], check=False)

    def schedule_remove_v6(self, ip6, delay_sec):
        if not ip6:
            return
        try:
            norm = str(ipaddress.IPv6Address(ip6))
        except ValueError:
            return
        if norm in self.preserve_v6:
            return
        if self.dry_run:
            log(f"[DRY-RUN] schedule removal of {norm} in {delay_sec}s")
            return
        subprocess.Popen(
            ["bash", "-c", f"sleep {int(delay_sec)} && ip -6 addr del {norm}/64 dev {self.iface} 2>/dev/null || true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def warmup_ndp(self, ip6):
        if self.dry_run:
            return
        self.sleep(self.ndp_warmup_sec)
        self.run_cmd(
            ["ping", "-6", "-I", ip6, "-c", "3", "-i", "0.4", "-W", "2", "2606:4700:4700::1111"],
            check=False,
            timeout=10,
        )

    def tcp_connect_v6(self, dst_ip, port, src_ip=None, timeout=3.0):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if src_ip:
                s.bind((src_ip, 0))
            s.connect((dst_ip, port))
            return True
        except Exception:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    # ---------------- Local Self-Heal ----------------

    def local_self_heal(self, current_ip):
        """
        Verify local IPv6 binding, systemd services, optional nftables & Xray users,
        and local TCP connectivity to [current_ip]:PROXY_PORT.
        Returns (local_ok: bool, healed_actions: list[str]).
        """
        actions = []

        # 1. Ensure current_ipv6 is bound on interface
        if current_ip and not self.iface_has_v6(current_ip):
            log(f"LOCAL HEAL: {current_ip} missing on {self.iface}, restoring")
            self.bind_v6(current_ip)
            self.warmup_ndp(current_ip)
            actions.append("restored_ipv6")

        # 2. Ensure optional nftables IPv4-drop rule is loaded
        if self.enforce_nft_v4_drop:
            p = self.run_cmd(["nft", "list", "ruleset"])
            if f"dport {self.proxy_port} drop" not in p.stdout:
                log("LOCAL HEAL: nftables IPv4 drop rule missing, reloading /etc/nftables.conf")
                if not self.dry_run:
                    self.run_cmd(["nft", "-f", "/etc/nftables.conf"], check=False)
                actions.append("reloaded_nftables")

        # 3. Ensure monitored systemd services are active
        for svc in self.monitor_services:
            p = self.run_cmd(["systemctl", "is-active", svc])
            if p.stdout.strip() != "active":
                log(f"LOCAL HEAL: service {svc} is {p.stdout.strip() or 'inactive'}, restarting")
                if not self.dry_run:
                    self.run_cmd(["systemctl", "restart", svc], check=False)
                actions.append(f"restarted:{svc}")

        if any(a.startswith("restarted:") for a in actions):
            self.sleep(2.5)

        # 4. Optional Xray inbound user-count check (catches silent sidecar sync drop)
        if self.xray_api and self.xray_inbounds and self.xray_sidecar:
            zero_tags = []
            for tag in self.xray_inbounds:
                p = self.run_cmd([self.xray_bin, "api", "inbounduser", "-s", self.xray_api, f"-tag={tag}"])
                if p.returncode == 0:
                    try:
                        users = json.loads(p.stdout).get("users", [])
                        if len(users) == 0:
                            zero_tags.append(tag)
                    except Exception:
                        pass
            if len(zero_tags) == len(self.xray_inbounds) and zero_tags:
                log(f"LOCAL HEAL: all monitored Xray inbounds have 0 users ({zero_tags}), restarting {self.xray_sidecar}")
                if not self.dry_run:
                    self.run_cmd(["systemctl", "restart", self.xray_sidecar], check=False)
                    self.sleep(3.0)
                actions.append(f"resynced:{self.xray_sidecar}")

        # 5. Local TCP handshake to [current_ip]:PROXY_PORT
        local_ok = self.tcp_connect_v6(current_ip, self.proxy_port, timeout=2.5)
        if not local_ok and self.monitor_services:
            primary_svc = self.monitor_services[0]
            log(f"LOCAL HEAL: local TCP connect [{current_ip}]:{self.proxy_port} failed, restarting {primary_svc}")
            if not self.dry_run:
                self.run_cmd(["systemctl", "restart", primary_svc], check=False)
                self.sleep(2.5)
            actions.append(f"restarted_port_fail:{primary_svc}")
            local_ok = self.tcp_connect_v6(current_ip, self.proxy_port, timeout=2.5)

        return local_ok, actions

    # ---------------- Globalping Primary Probe ----------------

    def _gp_headers(self):
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        tok = self.cfg.get("GLOBALPING_TOKEN", "").strip()
        if tok:
            h["Authorization"] = f"Bearer {tok}"
        return h

    def query_globalping_limits(self):
        try:
            req = urllib.request.Request(
                "https://api.globalping.io/v1/limits",
                headers=self._gp_headers(),
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.load(r)
            return data.get("rateLimit", {}).get("measurements", {}).get("create", {})
        except Exception as e:
            return {"error": str(e)}

    def globalping_probe_cn(self, target_ip):
        """
        Run forward TCP probe from mainland China (Telecom + Unicom + Mobile)
        via Globalping API.
        Returns dict:
          {
            "ok": bool,          # False if Globalping API itself failed/unavailable
            "finished": int,
            "passed_carriers": set[str],
            "failed_carriers": set[str],
            "details": list[str],
            "error": str|None,
          }
        """
        location_sets = [
            [
                {"magic": "CN+AS4134", "limit": 1},
                {"magic": "CN+AS4837", "limit": 1},
                {"magic": "CN+China Mobile", "limit": 1},
            ],
            [{"country": "CN", "limit": 3}],
        ]

        created = None
        last_err = None
        for locs in location_sets:
            payload = {
                "type": "ping",
                "target": target_ip,
                "locations": locs,
                "measurementOptions": {
                    "protocol": "TCP",
                    "port": self.proxy_port,
                    "packets": 3,
                },
            }
            req = urllib.request.Request(
                "https://api.globalping.io/v1/measurements",
                data=json.dumps(payload).encode("utf-8"),
                headers=self._gp_headers(),
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = json.load(r)
                if data.get("id") and int(data.get("probesCount", 0)) >= 2:
                    created = data
                    break
                last_err = f"insufficient_probes:{data.get('probesCount', 0)}"
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace")[:200]
                last_err = f"http_{e.code}:{body}"
                if e.code == 429:
                    break
            except Exception as e:
                last_err = str(e)

        if not created:
            return {
                "ok": False,
                "finished": 0,
                "passed_carriers": set(),
                "failed_carriers": set(),
                "details": [],
                "error": last_err or "create_failed",
            }

        mid = created["id"]
        url = f"https://api.globalping.io/v1/measurements/{mid}"
        for _ in range(12):
            self.sleep(2)
            try:
                greq = urllib.request.Request(url, headers=self._gp_headers())
                with urllib.request.urlopen(greq, timeout=15) as r:
                    res = json.load(r)
                if res.get("status") == "finished":
                    finished = 0
                    passed_carriers = set()
                    failed_carriers = set()
                    details = []
                    for item in res.get("results", []):
                        rres = item.get("result", {})
                        if rres.get("status") != "finished":
                            continue
                        finished += 1
                        probe = item.get("probe", {})
                        carrier = classify_cn_carrier(probe.get("asn"), probe.get("network", ""))
                        rcv = int((rres.get("stats") or {}).get("rcv") or 0)
                        city = probe.get("city") or "?"
                        if rcv > 0:
                            passed_carriers.add(carrier)
                        else:
                            failed_carriers.add(carrier)
                        details.append(f"{carrier}({city}):{rcv}/3")
                    # If same carrier appeared twice and one passed, count carrier as passed
                    failed_carriers -= passed_carriers
                    return {
                        "ok": finished >= 2,
                        "finished": finished,
                        "passed_carriers": passed_carriers,
                        "failed_carriers": failed_carriers,
                        "details": details,
                        "error": None if finished >= 2 else "too_few_finished_probes",
                    }
            except Exception as e:
                last_err = str(e)

        return {
            "ok": False,
            "finished": 0,
            "passed_carriers": set(),
            "failed_carriers": set(),
            "details": [],
            "error": last_err or "poll_timeout",
        }

    # ---------------- Reverse CN Fallback Probe ----------------

    def reverse_probe_cn(self, src_ip):
        """
        Fallback when Globalping API is unavailable/rate-limited.
        Tests 9 static mainland China IPv6 endpoints (3 Telecom, 3 Unicom, 3 Mobile).
        A carrier passes if >= 1 of its 3 static endpoints accepts TCP handshake.
        """
        by_isp = {"telecom": 0, "unicom": 0, "mobile": 0}
        for isp, dst, port, _ in DEFAULT_CN_FALLBACK_PROBES:
            if self.tcp_connect_v6(dst, port, src_ip=src_ip, timeout=3.0):
                by_isp[isp] += 1
        passed = {isp for isp, cnt in by_isp.items() if cnt >= 1}
        failed = {isp for isp, cnt in by_isp.items() if cnt == 0}
        details = [f"{isp}:{cnt}/3" for isp, cnt in by_isp.items()]
        return {
            "ok": True,
            "finished": 3,
            "passed_carriers": passed,
            "failed_carriers": failed,
            "details": details,
            "error": None,
        }

    # ---------------- Cloudflare DNS & Alerts ----------------

    def update_cf_aaaa(self, new_ip):
        token = self.cfg["CF_TOKEN"]
        zone = self.cfg["CF_ZONE_ID"]
        rec_id = self.cfg["CF_RECORD_ID"]
        domain = self.cfg["DOMAIN"]
        ttl = int(self.cfg.get("DNS_TTL", "60"))
        if self.dry_run:
            log(f"[DRY-RUN] Cloudflare PUT AAAA {domain} -> {new_ip} (ttl={ttl})")
            return {"name": domain, "content": new_ip, "ttl": ttl}
        payload = json.dumps({
            "type": "AAAA",
            "name": domain,
            "content": new_ip,
            "ttl": ttl,
            "proxied": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rec_id}",
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        if not data.get("success"):
            raise RuntimeError(f"Cloudflare DNS update failed: {data}")
        return data["result"]

    def send_alert(self, title, body):
        msg = f"[ipv6-watchdog] {title}\n{body}"
        tg_token = self.cfg.get("TG_BOT_TOKEN", "").strip()
        tg_chat = self.cfg.get("TG_CHAT_ID", "").strip()
        webhook = self.cfg.get("WEBHOOK_URL", "").strip()

        if self.dry_run:
            if tg_token or webhook:
                log(f"[DRY-RUN] Alert: {title} | {body}")
            return

        if tg_token and tg_chat:
            try:
                payload = json.dumps({"chat_id": tg_chat, "text": msg}).encode("utf-8")
                req = urllib.request.Request(
                    f"https://api.telegram.org/bot{tg_token}/sendMessage",
                    data=payload,
                    headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10).close()
            except Exception as e:
                log(f"Telegram alert failed: {e}")

        if webhook:
            try:
                payload = json.dumps({"title": title, "message": body, "text": msg}).encode("utf-8")
                req = urllib.request.Request(
                    webhook,
                    data=payload,
                    headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=10).close()
            except Exception as e:
                log(f"Webhook alert failed: {e}")

    # ---------------- Core Straight-Line SLA Logic ----------------

    def _is_blocked(self, probe_res):
        return len(probe_res["failed_carriers"]) >= self.fail_carrier_threshold

    def _is_healthy(self, probe_res):
        return len(probe_res["passed_carriers"]) >= self.fail_carrier_threshold and not self._is_blocked(probe_res)

    def _commit_switch(self, state, old_ip, new_ip, reason):
        rec = self.update_cf_aaaa(new_ip)
        now = self.now()
        state["current_ipv6"] = new_ip
        state["last_switch_ts"] = now
        state["last_status"] = "switched"
        hist = state.get("switch_history", [])
        hist.append({"ts": now, "old": old_ip, "new": new_ip, "reason": reason})
        state["switch_history"] = hist[-30:]
        if not self.dry_run:
            save_state(self.state_file, state)
        log(f"SWITCHED DNS {rec['name']}: {old_ip} -> {new_ip} (ttl={rec['ttl']}, reason={reason})")
        if old_ip and old_ip != new_ip:
            log(f"Draining old IPv6 {old_ip} for {self.old_ip_grace}s before removal")
            self.schedule_remove_v6(old_ip, self.old_ip_grace)
        self.send_alert(
            f"IPv6 Rotated ({self.cfg.get('DOMAIN', '')})",
            f"Reason: {reason}\nOld: {old_ip}\nNew: {new_ip}\nTTL: {rec['ttl']}s",
        )

    def _check_guardrails(self, state):
        now = self.now()
        since_last = now - int(state.get("last_switch_ts", 0))
        if since_last < self.cooldown:
            return False, f"cooldown_active({since_last}s<{self.cooldown}s)"
        recent_24h = [h for h in state.get("switch_history", []) if now - int(h.get("ts", 0)) < 86400]
        if len(recent_24h) >= self.max_switches_24h:
            return False, f"daily_cap_reached({len(recent_24h)}/{self.max_switches_24h})"
        return True, "ok"

    def _recent_exclusions(self, state, current_ip):
        ex = set(self.preserve_v6)
        if current_ip:
            ex.add(current_ip)
        for h in state.get("switch_history", [])[-10:]:
            if h.get("old"):
                ex.add(h["old"])
            if h.get("new"):
                ex.add(h["new"])
        return ex

    def check(self):
        state = load_state(self.state_file)
        cur = state.get("current_ipv6", "").strip()
        if not cur:
            raise RuntimeError("current_ipv6 is empty in state.json")

        # Step 1: Primary forward CN 3-carrier check via Globalping
        mode = "globalping"
        res1 = self.globalping_probe_cn(cur)
        if not res1["ok"]:
            log(f"Globalping unavailable ({res1['error']}), degrading to local reverse 3-carrier CN probe")
            mode = "reverse_fallback"
            res1 = self.reverse_probe_cn(cur)

        summary = f"mode={mode} cur=[{','.join(res1['details'])}]"
        state["last_check_ts"] = self.now()

        # Fast happy path: >= 2 carriers healthy -> done!
        if self._is_healthy(res1):
            state["last_status"] = "healthy"
            state["last_check_summary"] = summary
            if not self.dry_run:
                save_state(self.state_file, state)
            log(f"HEALTHY | {summary}")
            return "healthy"

        if not self._is_blocked(res1):
            # Inconclusive (e.g., 1 passed, 1 failed) -> do not overreact
            state["last_status"] = "degraded_single"
            state["last_check_summary"] = summary
            if not self.dry_run:
                save_state(self.state_file, state)
            log(f"DEGRADED (<{self.fail_carrier_threshold} carriers failed, holding) | {summary}")
            return "degraded_single"

        # Step 2: >= 2 carriers failed -> triage local health BEFORE blaming GFW
        log(f"ALERT: >={self.fail_carrier_threshold} CN carriers failed | {summary} -> running local self-heal")
        local_ok, healed = self.local_self_heal(cur)
        if healed or not local_ok:
            status = "local_healed" if local_ok else "local_unhealthy"
            state["last_status"] = status
            state["last_check_summary"] = f"{summary} | local_ok={local_ok} actions={healed}"
            if not self.dry_run:
                save_state(self.state_file, state)
            log(f"{status.upper()} (skipping IP rotation) | actions={healed}")
            if not local_ok or healed:
                self.send_alert(f"Local Health Event ({status})", f"Actions: {healed}\nLocal OK: {local_ok}")
            return status

        # Step 3: Local is 100% healthy -> spawn a FRESH random /64 successor as control + hot replacement
        cand = generate_random_v6(self.prefix64, self._recent_exclusions(state, cur))
        log(f"Local healthy; binding fresh random successor {cand} as control probe")
        self.bind_v6(cand)
        self.warmup_ndp(cand)

        probe_fn = self.globalping_probe_cn if mode == "globalping" else self.reverse_probe_cn
        res_cand = probe_fn(cand)
        summary += f" | cand({cand})=[{','.join(res_cand['details'])}]"

        if not res_cand["ok"] or not self._is_healthy(res_cand):
            log(f"SUBNET_OR_UPSTREAM_OUTAGE: fresh successor {cand} also failed; cleaning up temp IP and keeping DNS")
            self.remove_v6(cand)
            state["last_status"] = "subnet_or_upstream_outage"
            state["last_check_summary"] = summary
            if not self.dry_run:
                save_state(self.state_file, state)
            self.send_alert(
                f"Subnet/Upstream Outage ({self.cfg.get('DOMAIN', '')})",
                f"Both current ({cur}) and fresh random successor ({cand}) failed CN check.\n{summary}",
            )
            return "subnet_or_upstream_outage"

        # Step 4: Fresh successor PASSED! Wait RECHECK_DELAY_SECONDS (default 10s) and retest current_ipv6
        log(f"Successor {cand} PASSED CN check! Waiting {self.recheck_delay}s to recheck {cur}...")
        self.sleep(self.recheck_delay)
        res2 = probe_fn(cur)
        summary += f" | recheck=[{','.join(res2['details'])}]"

        if not res2["ok"] or not self._is_blocked(res2):
            log(f"TRANSIENT_BLIP: {cur} recovered on {self.recheck_delay}s recheck; removing temp {cand}")
            self.remove_v6(cand)
            state["last_status"] = "transient_recovered"
            state["last_check_summary"] = summary
            if not self.dry_run:
                save_state(self.state_file, state)
            return "transient_recovered"

        # Step 5: Confirmed blocked! Enforce cooldown & 24h cap, then commit switch to already-verified successor
        allowed, guard_reason = self._check_guardrails(state)
        if not allowed:
            log(f"SWITCH_DEFERRED ({guard_reason}): removing temp {cand} to protect /64")
            self.remove_v6(cand)
            state["last_status"] = f"switch_deferred:{guard_reason}"
            state["last_check_summary"] = summary
            if not self.dry_run:
                save_state(self.state_file, state)
            self.send_alert(
                f"IPv6 Switch Deferred ({self.cfg.get('DOMAIN', '')})",
                f"Current {cur} confirmed blocked, but switch deferred: {guard_reason}\n{summary}",
            )
            return f"switch_deferred:{guard_reason}"

        state["last_check_summary"] = summary
        self._commit_switch(state, cur, cand, f"confirmed_{mode}_blocked")
        return "switched"

    def force_switch(self):
        state = load_state(self.state_file)
        old_ip = state.get("current_ipv6", "").strip()
        cand = generate_random_v6(self.prefix64, self._recent_exclusions(state, old_ip))
        log(f"FORCE SWITCH: binding & verifying fresh IPv6 {cand}")
        self.bind_v6(cand)
        self.warmup_ndp(cand)
        res = self.globalping_probe_cn(cand)
        if not res["ok"]:
            res = self.reverse_probe_cn(cand)
        if not self._is_healthy(res):
            self.remove_v6(cand)
            raise RuntimeError(f"Aborting force-switch: candidate {cand} failed CN verification: {res['details']}")
        state["last_check_ts"] = self.now()
        state["last_check_summary"] = f"force_switch cand=[{','.join(res['details'])}]"
        self._commit_switch(state, old_ip, cand, "manual_force_switch")
        return cand

    def restore(self):
        state = load_state(self.state_file)
        cur = state.get("current_ipv6", "").strip()
        if not cur:
            log("No current_ipv6 in state.json to restore")
            return
        self.bind_v6(cur)
        self.warmup_ndp(cur)
        log(f"Restored active proxy IPv6 {cur}/64 on {self.iface}")


def main():
    ap = argparse.ArgumentParser(description="High-SLA IPv6 /64 GFW Watchdog & Auto-Rotator")
    ap.add_argument("--config-dir", default=str(DEFAULT_BASE_DIR), help="Directory containing config.env & state.json")
    ap.add_argument("--check", action="store_true", help="Run one SLA check cycle")
    ap.add_argument("--restore", action="store_true", help="Restore active proxy IPv6 on boot")
    ap.add_argument("--force-switch", action="store_true", help="Immediately verify & rotate to a fresh random IPv6")
    ap.add_argument("--self-heal", action="store_true", help="Run local service/IPv6/nftables self-heal only")
    ap.add_argument("--status", action="store_true", help="Print status JSON & Globalping quota")
    ap.add_argument("--dry-run", action="store_true", help="Simulate actions without changing IP/DNS/services")
    args = ap.parse_args()

    base_dir = Path(args.config_dir)
    cfg = parse_env_file(base_dir / "config.env")
    wd = Watchdog(cfg, base_dir=base_dir, dry_run=args.dry_run)

    if args.restore:
        wd.restore()
    elif args.self_heal:
        state = load_state(wd.state_file)
        ok, actions = wd.local_self_heal(state.get("current_ipv6", ""))
        log(f"SELF-HEAL finished: local_ok={ok}, actions={actions}")
    elif args.force_switch:
        wd.force_switch()
    elif args.check:
        wd.check()
    elif args.status:
        state = load_state(wd.state_file)
        out = {
            "domain": cfg.get("DOMAIN", ""),
            "iface": wd.iface,
            "proxy_port": wd.proxy_port,
            "state": state,
            "globalping_limits": wd.query_globalping_limits(),
        }
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
