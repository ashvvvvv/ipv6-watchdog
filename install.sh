#!/usr/bin/env bash
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/ashvvvvv/ipv6-watchdog/main"
INSTALL_DIR="/opt/ipv6-watchdog"

ACTION="install"
CF_TOKEN=""
DOMAIN=""
PROXY_PORT="443"
INTERVAL="90s"
IFACE=""
PREFIX64=""
PRESERVE_IPV6=""
CURRENT_IPV6=""
MONITOR_SERVICES="xray.service"
DROP_V4_PORT="0"
GLOBALPING_TOKEN=""
TG_BOT_TOKEN=""
TG_CHAT_ID=""
WEBHOOK_URL=""
RECHECK_DELAY="10"
FAIL_CARRIERS="2"
COOLDOWN="1800"
MAX_24H="3"

usage() {
  cat <<'EOF'
ipv6-watchdog one-click installer / upgrader / uninstaller

Usage:
  sudo bash install.sh [options]

Actions:
  --upgrade                 Update watchdog.py only (preserves config.env & state.json)
  --uninstall               Stop timers/services and remove /opt/ipv6-watchdog
  -h, --help                Show this help

Install Options (omit to use interactive prompts):
  --cf-token <token>        Cloudflare API Token (Zone:DNS:Edit)
  --domain <fqdn>           Pure AAAA domain name (e.g. edge.example.com)
  --port <port>             Proxy TCP port to monitor (default: 443)
  --interval <systemd-time> Timer interval (default: 90s; 60s/90s/120s)
  --iface <dev>             Network interface (auto-detected if omitted)
  --prefix64 <prefix>       IPv6 /64 prefix (auto-detected if omitted)
  --preserve-v6 <ip6,...>   System IPv6(s) never removed (auto-detected if omitted)
  --current-v6 <ip6>        Use an existing IPv6 instead of generating a random one
  --services <svc,...>      Comma-separated systemd services to self-heal (default: xray.service)
  --drop-v4-port            Configure nftables to drop incoming IPv4 on --port
  --gp-token <token>        Optional Globalping API token (doubles quota 250 -> 500/hr)
  --tg-token <token>        Optional Telegram Bot token for alerts
  --tg-chat-id <id>         Optional Telegram Chat ID for alerts
  --webhook-url <url>       Optional JSON Webhook URL for alerts
  --recheck-delay <sec>     Seconds before rechecking blocked IPv6 (default: 10)
  --fail-carriers <n>       Min distinct CN carriers failing to trigger (default: 2)
  --cooldown <sec>          Cooldown seconds between switches (default: 1800)
  --max-24h <n>             Max automatic switches per 24h (default: 3)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --upgrade) ACTION="upgrade"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    --cf-token) CF_TOKEN="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --port) PROXY_PORT="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --prefix64) PREFIX64="$2"; shift 2 ;;
    --preserve-v6) PRESERVE_IPV6="$2"; shift 2 ;;
    --current-v6) CURRENT_IPV6="$2"; shift 2 ;;
    --services) MONITOR_SERVICES="$2"; shift 2 ;;
    --drop-v4-port) DROP_V4_PORT="1"; shift ;;
    --gp-token) GLOBALPING_TOKEN="$2"; shift 2 ;;
    --tg-token) TG_BOT_TOKEN="$2"; shift 2 ;;
    --tg-chat-id) TG_CHAT_ID="$2"; shift 2 ;;
    --webhook-url) WEBHOOK_URL="$2"; shift 2 ;;
    --recheck-delay) RECHECK_DELAY="$2"; shift 2 ;;
    --fail-carriers) FAIL_CARRIERS="$2"; shift 2 ;;
    --cooldown) COOLDOWN="$2"; shift 2 ;;
    --max-24h) MAX_24H="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Error: please run as root (sudo bash install.sh ...)" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required." >&2
  exit 1
fi

download_watchdog() {
  mkdir -p "$INSTALL_DIR"
  chmod 0700 "$INSTALL_DIR"
  if [[ -f "./watchdog.py" ]]; then
    cp "./watchdog.py" "$INSTALL_DIR/watchdog.py.new"
  else
    curl -fsSL "$REPO_RAW/watchdog.py" -o "$INSTALL_DIR/watchdog.py.new"
  fi
  chmod 0700 "$INSTALL_DIR/watchdog.py.new"
  mv "$INSTALL_DIR/watchdog.py.new" "$INSTALL_DIR/watchdog.py"
}

if [[ "$ACTION" == "uninstall" ]]; then
  systemctl disable --now ipv6-watchdog.timer ipv6-watchdog.service proxy-ipv6-restore.service 2>/dev/null || true
  rm -f /etc/systemd/system/ipv6-watchdog.timer \
        /etc/systemd/system/ipv6-watchdog.service \
        /etc/systemd/system/proxy-ipv6-restore.service \
        /etc/sysctl.d/99-ipv6-watchdog.conf
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR"
  echo "ipv6-watchdog uninstalled cleanly."
  exit 0
fi

if [[ "$ACTION" == "upgrade" ]]; then
  download_watchdog
  systemctl daemon-reload
  echo "ipv6-watchdog upgraded at $INSTALL_DIR/watchdog.py (config.env & state.json preserved)."
  "$INSTALL_DIR/watchdog.py" --status || true
  exit 0
fi

# --- Auto-detect default IPv6 interface, system IPv6, and /64 prefix ---
if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -6 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  IFACE="${IFACE:-eth0}"
fi

AUTO_V6="$(ip -6 -o addr show dev "$IFACE" scope global 2>/dev/null | awk '!/temporary|deprecated/{print $4; exit}')"
AUTO_V6_IP="${AUTO_V6%%/*}"

if [[ -z "$PRESERVE_IPV6" && -n "$AUTO_V6_IP" ]]; then
  PRESERVE_IPV6="$AUTO_V6_IP"
fi

if [[ -z "$PREFIX64" && -n "$AUTO_V6_IP" ]]; then
  PREFIX64="$(python3 -c "import ipaddress; n=ipaddress.IPv6Network('${AUTO_V6_IP}/64', strict=False); print(':'.join(f'{int(h,16):x}' for h in n.network_address.exploded.split(':')[:4]))")"
fi

prompt_if_empty() {
  local var_name="$1"
  local prompt_msg="$2"
  local default_val="${3:-}"
  local cur_val="${!var_name}"
  if [[ -z "$cur_val" ]]; then
    if [[ -r /dev/tty ]]; then
      if [[ -n "$default_val" ]]; then
        read -r -p "${prompt_msg} [${default_val}]: " cur_val </dev/tty
        cur_val="${cur_val:-$default_val}"
      else
        read -r -p "${prompt_msg}: " cur_val </dev/tty
      fi
      printf -v "$var_name" '%s' "$cur_val"
    elif [[ -n "$default_val" ]]; then
      printf -v "$var_name" '%s' "$default_val"
    fi
  fi
}

prompt_if_empty CF_TOKEN "Cloudflare API Token (Zone:DNS:Edit)"
prompt_if_empty DOMAIN "Pure AAAA Domain (e.g. edge.example.com)"
prompt_if_empty IFACE "Network Interface" "$IFACE"
prompt_if_empty PREFIX64 "IPv6 /64 Prefix (first 4 hextets)" "$PREFIX64"
prompt_if_empty PRESERVE_IPV6 "System IPv6 to preserve" "$PRESERVE_IPV6"

if [[ -z "$CF_TOKEN" || -z "$DOMAIN" || -z "$PREFIX64" ]]; then
  echo "Error: --cf-token, --domain, and --prefix64 are required." >&2
  exit 1
fi

echo "==> Installing watchdog script to $INSTALL_DIR/watchdog.py"
download_watchdog

# Enable ip_nonlocal_bind so proxy daemons never fail bind during reboot DAD
cat <<'EOF' > /etc/sysctl.d/99-ipv6-watchdog.conf
net.ipv6.ip_nonlocal_bind = 1
EOF
sysctl -p /etc/sysctl.d/99-ipv6-watchdog.conf >/dev/null

# Pick or generate initial proxy IPv6
if [[ -z "$CURRENT_IPV6" ]]; then
  CURRENT_IPV6="$(python3 -c "import sys; sys.path.insert(0, '$INSTALL_DIR'); import watchdog; print(watchdog.generate_random_v6('$PREFIX64', set('$PRESERVE_IPV6'.split(','))))")"
fi

echo "==> Binding initial proxy IPv6: $CURRENT_IPV6/64 on $IFACE"
ip -6 addr replace "${CURRENT_IPV6}/64" dev "$IFACE" preferred_lft 0
sleep 2
ping -6 -I "$CURRENT_IPV6" -c 3 -i 0.4 -W 2 2606:4700:4700::1111 >/dev/null 2>&1 || true

# Resolve Cloudflare Zone ID and create/update AAAA record (TTL 60, DNS Only)
echo "==> Configuring Cloudflare AAAA record: $DOMAIN -> $CURRENT_IPV6 (TTL 60, DNS Only)"
CF_META="$(CF_TOKEN="$CF_TOKEN" DOMAIN="$DOMAIN" CURRENT_IPV6="$CURRENT_IPV6" python3 - <<'PYEOF'
import json, os, urllib.request

token = os.environ["CF_TOKEN"]
domain = os.environ["DOMAIN"].strip().rstrip(".")
ipv6 = os.environ["CURRENT_IPV6"].strip()

def cf(method, path, body=None):
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "ipv6-watchdog-installer/2.0",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        data = json.load(r)
    if not data.get("success"):
        raise RuntimeError(f"Cloudflare API error: {data}")
    return data["result"]

zones = cf("GET", "/zones?per_page=50")
matched = None
for z in sorted(zones, key=lambda x: len(x["name"]), reverse=True):
    zname = z["name"].rstrip(".")
    if domain == zname or domain.endswith("." + zname):
        matched = z
        break
if not matched:
    raise RuntimeError(f"No matching Cloudflare zone found for {domain}")

zone_id = matched["id"]
recs = cf("GET", f"/zones/{zone_id}/dns_records?type=AAAA&name={domain}")
payload = {"type": "AAAA", "name": domain, "content": ipv6, "ttl": 60, "proxied": False}
if recs:
    rec = cf("PUT", f"/zones/{zone_id}/dns_records/{recs[0]['id']}", payload)
else:
    rec = cf("POST", f"/zones/{zone_id}/dns_records", payload)

print(f"{zone_id}|{rec['id']}")
PYEOF
)"

CF_ZONE_ID="${CF_META%%|*}"
CF_RECORD_ID="${CF_META##*|}"

if [[ "$DROP_V4_PORT" == "1" ]]; then
  echo "==> Configuring nftables to drop external IPv4 port $PROXY_PORT"
  if ! command -v nft >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables
    else
      echo "Warning: nftables not found; please install nftables manually." >&2
    fi
  fi
  if command -v nft >/dev/null 2>&1; then
    cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset

table ip proxy_filter {
    chain input {
        type filter hook input priority 0; policy accept;
        iif "lo" accept
        tcp dport ${PROXY_PORT} drop
        udp dport ${PROXY_PORT} drop
    }
}
EOF
    nft -f /etc/nftables.conf
    systemctl enable nftables >/dev/null 2>&1 || true
  fi
fi

# Write 0600 config.env
umask 0077
cat <<EOF > "$INSTALL_DIR/config.env"
CF_TOKEN=${CF_TOKEN}
CF_ZONE_ID=${CF_ZONE_ID}
CF_RECORD_ID=${CF_RECORD_ID}
DOMAIN=${DOMAIN}
DNS_TTL=60
IFACE=${IFACE}
PREFIX64=${PREFIX64}
PRESERVE_IPV6=${PRESERVE_IPV6}
PROXY_PORT=${PROXY_PORT}
FAIL_CARRIER_THRESHOLD=${FAIL_CARRIERS}
RECHECK_DELAY_SECONDS=${RECHECK_DELAY}
COOLDOWN_SECONDS=${COOLDOWN}
MAX_SWITCHES_24H=${MAX_24H}
OLD_IP_GRACE_SECONDS=120
NDP_WARMUP_SECONDS=2
MONITOR_SERVICES=${MONITOR_SERVICES}
ENFORCE_NFT_DROP_V4=${DROP_V4_PORT}
GLOBALPING_TOKEN=${GLOBALPING_TOKEN}
TG_BOT_TOKEN=${TG_BOT_TOKEN}
TG_CHAT_ID=${TG_CHAT_ID}
WEBHOOK_URL=${WEBHOOK_URL}
EOF
chmod 0600 "$INSTALL_DIR/config.env"

cat <<EOF > "$INSTALL_DIR/state.json"
{
  "current_ipv6": "${CURRENT_IPV6}",
  "last_check_ts": 0,
  "last_status": "initialized",
  "last_check_summary": "installed",
  "last_switch_ts": 0,
  "switch_history": []
}
EOF
chmod 0600 "$INSTALL_DIR/state.json"

# Install systemd units
umask 0022
cat <<EOF > /etc/systemd/system/proxy-ipv6-restore.service
[Unit]
Description=Restore active proxy IPv6 address on boot
After=network-online.target
Wants=network-online.target
Before=xray.service sing-box.service

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/watchdog.py --restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/ipv6-watchdog.service
[Unit]
Description=High-SLA IPv6 /64 GFW Watchdog check
After=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/watchdog.py --check
EOF

cat <<EOF > /etc/systemd/system/ipv6-watchdog.timer
[Unit]
Description=Run ipv6-watchdog every ${INTERVAL}

[Timer]
OnBootSec=60s
OnUnitActiveSec=${INTERVAL}
AccuracySec=5s
Persistent=false

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable proxy-ipv6-restore.service
systemctl enable --now ipv6-watchdog.timer

echo "==> Running initial live check..."
"$INSTALL_DIR/watchdog.py" --check || true

echo ""
echo "=========================================================="
echo " ipv6-watchdog installed successfully!"
echo " Domain:      ${DOMAIN} (AAAA -> ${CURRENT_IPV6}, TTL 60s)"
echo " Interval:    ${INTERVAL}"
echo " Config:      ${INSTALL_DIR}/config.env (0600)"
echo " Commands:"
echo "   ${INSTALL_DIR}/watchdog.py --status"
echo "   ${INSTALL_DIR}/watchdog.py --check"
echo "   ${INSTALL_DIR}/watchdog.py --force-switch"
echo "   journalctl -u ipv6-watchdog -n 30 --no-pager"
echo "=========================================================="
