# Passwall Android (Magisk / KernelSU Transparent Proxy)

[English](README.md) | [فارسی](README_FA.md)

OpenWrt Passwall-style transparent proxy module for Android 6.0 through Android 16 (`armeabi-v7a` and `arm64-v8a`), powered by `xray-core` and an embedded ES5 web dashboard.

> **Project Origin & Disclaimer:**  
> The name and concept of this project were inspired by OpenWrt's **Passwall** transparent proxy tool. However, this project is completely separate and independent from OpenWrt Passwall's source code—it was designed, engineered, and written from scratch in Go specifically for Android, Magisk, and KernelSU environments.

## Features

- **System-Wide & Hotspot/NAT Transparent Proxy:** Captures local apps (`OUTPUT`) and Wi-Fi hotspot / USB tethering clients (`PREROUTING`) across all interfaces (`wlan0`, `ap0`, `swlan0`, `rndis0`). Features multi-interface `rp_filter=0` mitigation, `route_localnet=1`, tethering NAT masquerading, and forward chain acceptance so connected devices never get "no internet".
- **Android 6.0+ & ARMv7 Compatibility:** Automatically detects kernel `xt_TPROXY` support at startup and falls back to `nat REDIRECT` on legacy Android 6 vendor kernels, with `GOGC=40` and `GOMEMLIMIT=48MiB` memory tuning.
- **Android 12+ eBPF & Hardware Tethering Offload Bypass & Netd Watchdog:** Disables tether hardware offload (`settings put global tether_offload_disabled 1`, `cmd connectivity tether offload set false`, and `ndc`) so hotspot traffic traverses Netfilter, and dynamically restores routing rules and sysctls if Android resets tables during network switches.
- **Zero-Loss Config & UI State Upgrades & Factory Reset:** Automatically preserves base Xray configuration (`config.json`) and UI state (`state.json` - saved nodes, subscriptions, active node, DNS settings, and per-app split tunnel UIDs) across Magisk and KernelSU module ZIP updates via persistent storage (`/data/adb/passwall/`). Includes one-click **Reset to Default** in the Web UI and CLI (`passwall reset-config`).
- **Domain-Aware Routing & Leak Prevention:** Bridges Layer 3/4 Netfilter IP packets to Layer 7 domain routing using UDP/TCP port 53 DNS interception and TLS/HTTP/QUIC SNI sniffing (`sniffing.destOverride = ["http", "tls", "quic"]`). Rejects Android Private DNS (DoT port 853) to prevent leaks, blocks IPv6 via kernel sysctls and `ip6tables` drop rules, blocks QUIC (UDP 443) to force standard TLS SNI sniffing, and preserves custom user routing rules.
- **Embedded Web Control Panel (`http://127.0.0.1:9090` or `http://<phone-ip>:9090` on LAN):**
  - Switch routing modes (`Rule`, `Global`, `Direct`) with deadlock-free domain resolution for proxy nodes.
  - Dedicated **DNS Settings** tab: configure Remote DNS (`tcp://1.1.1.1`, `https://dns.google/dns-query`, etc.), Direct DNS (`223.5.5.5`, `10.202.10.202`, etc.), and Query Strategy (`UseIPv4`, `UseIP`, `UseIPv6`).
  - Dedicated **Geo Rules Settings** tab: toggle domestic bypass (Iran / China), ad-blocking (`geosite:category-ads-all`), configure custom Direct, Proxy, and Block domain & IP lists, inspect `geoip.dat` and `geosite.dat` status, and update geo assets on-the-fly over direct WAN.
  - Import `vless://` (including `xhttp`, `ws`, `grpc`, `tls`, `reality`), `trojan://`, `vmess://`, `ss://`, and `hysteria2://` / `hy2://` links.
  - Fetch Base64/plain subscription URLs over direct WAN (`SO_MARK 0x02000000`) with optional SSL/TLS certificate verification bypass and scheduled background auto-updates.
  - Concurrent TCP/TLS latency tester with one-tap **Fastest** node selection.
  - Per-app UID split tunneling (`Bypass Selected` or `Proxy Only Selected`) while keeping hotspot clients proxied.

## Configuration & Usage Tutorial

<details>
<summary><b>📖 Full Configuration Tutorial (Click to Expand)</b></summary>

### 1. Accessing the Web Dashboard
After flashing the module in **Magisk**, **KernelSU**, or **APatch** and rebooting your device, the transparent proxy service starts automatically in the background.

- **On your Android device:** Open any web browser and navigate to:
  ```text
  http://127.0.0.1:9090
  ```
- **From another device on the same Wi-Fi / Hotspot (PC, tablet, laptop):**
  ```text
  http://<phone-ip>:9090
  ```
  *(Find your phone's IP address under **Settings -> About Phone -> Status Information -> IP address** or by running `ip addr show wlan0` in Termux/ADB).*

---

### 2. Header & Status Controls
The top card displays real-time daemon information and connectivity:
- **Status Badge:** Displays `RUNNING` (green) when both `xray-core` and Netfilter interception rules are active, or `STOPPED` (red).
- **Service Info:** Shows running Xray core version, Netfilter interception mode (`TPROXY (mangle)` on modern kernels or `REDIRECT (nat)` on legacy kernels), and the process PID.
- **Connectivity Monitor:** Tap **Check** to test live round-trip latency to **Google** (proxied WAN) and **GitHub** (direct/CDN).
- **Service Controls:**
  - `Start`: Launches Xray-core and sets up transparent Netfilter routing.
  - `Restart`: Reloads runtime configurations and restarts networking rules without dropping system sockets.
  - `Stop`: Stops Xray-core and flushes all Netfilter chains (`PASSWALL_PRE`, `PASSWALL_OUT`, etc.).

---

### 3. Routing Modes & Localhost Proxy
Select your preferred traffic routing strategy:
- **Rule Mode (Bypass IR / CN):** Domestic services, local banking apps, and non-blocked websites route direct through WAN without consuming proxy bandwidth. Censored/foreign websites route through the active proxy node.
- **Global Mode:** All outgoing traffic (except private RFC 1918 LAN ranges) is forwarded through the active proxy node.
- **Direct Mode:** Netfilter rules remain active, but all outbound traffic is routed direct via WAN.
- **Proxy Local Device (Localhost) Checkbox:**
  - **Enabled (Default):** Both local Android apps on your phone and tethered clients (Wi-Fi Hotspot / USB Tethering) are transparently proxied.
  - **Disabled:** Only Wi-Fi Hotspot and USB Tethering clients are proxied through the node; apps running locally on your phone route direct WAN. *(Ideal for using an Android device as a dedicated, low-power transparent VPN gateway).*

---

### 4. Nodes & Subscription Management (`Nodes & Sub` Tab)
- **Adding a Subscription:**
  1. Paste your subscription URL (HTTP/HTTPS Base64 format) into the **Subscription URL** field.
  2. If using self-signed certificates or CDNs with certificate discrepancies, check **Ignore SSL / TLS certificate errors**.
  3. Select an **Auto-Update** interval (`Every 6 Hours`, `Every 12 Hours`, `Every 24 Hours`, or `Off`).
  4. Click **Update Sub** to fetch immediately over direct WAN (`SO_MARK 0x02000000`), or **Save** to store settings.
- **Manual Node Import:**
  - Paste any supported sharing link into the **Manual URI Import** field and tap **Import & Connect**:
    - `vless://` (supports `reality`, `ws`, `xhttp`, `splithttp`, `grpc`, `tls`)
    - `trojan://`
    - `vmess://`
    - `ss://` (standard and legacy base64 formats)
    - `hysteria2://` / `hy2://`
- **Testing & Node Switching:**
  - Tap **Ping** next to any node to measure real-world round-trip time (ms).
  - Tap **Ping All** to test all imported nodes sequentially.
  - Tap **Fastest** to automatically test and switch to the lowest-latency reachable node.
  - Tap **Use** to make a specific node active immediately.

---

### 5. DNS Configuration (`DNS` Tab)
Passwall features an internal dokodemo-door DNS interception server running on port `1053` with TCP and UDP support:
- **Remote DNS (Proxied / Foreign):**
  The DNS resolver used for blocked and foreign domains through the proxy tunnel.
  - Presets: `tcp://1.1.1.1`, `1.1.1.1` (UDP), `tcp://8.8.8.8`, `https://1.1.1.1/dns-query` (Cloudflare DoH), `https://dns.google/dns-query` (Google DoH).
- **Direct DNS (Domestic / Node Resolution):**
  The DNS resolver used over direct WAN for domestic domains, active proxy node hostnames, and subscription links.
  - Presets: `1.1.1.1` (Cloudflare UDP), `localhost` (System DNS), `10.202.10.202` (Shecan), `77.88.8.8` (Yandex), `223.5.5.5` (AliDNS).
- **Query Strategy:**
  - `UseIPv4` *(Recommended)*: Resolves only A records, preventing IPv6 fallback delays and connection drops on networks without IPv6 proxy routing.
  - `UseIP`: Resolves both IPv4 and IPv6.
  - `UseIPv6`: Prefers AAAA records.
- Tap **Save & Apply DNS** to apply resolver changes and restart the engine.

---

### 6. Geo Rules & Routing Policy (`Geo Rules` Tab)
Fine-tune Layer 7 routing policies and geosite/geoip database rulesets:
- **Built-in Policy Toggles:**
  - **Bypass Iran Domestic Traffic:** Routes `domain:ir`, `geosite:ir`, `geosite:category-ir`, and `geoip:ir` direct via WAN.
  - **Bypass China Traffic:** Routes `geosite:cn` and `geoip:cn` direct via WAN.
  - **Block Advertisements & Tracking:** Routes `geosite:category-ads-all` to the `block` (blackhole) outbound.
- **Custom Routing Lists:**
  Add custom rules (one entry per line). Supports domains (`example.com`), domain tags (`domain:bank.ir`), geosite tags (`geosite:google`), IP addresses (`1.2.3.4`), CIDR blocks (`10.0.0.0/8`), and geoip tags (`geoip:telegram`):
  - **Direct / Bypass Domains & IPs:** Always routed directly over WAN.
  - **Force Proxy Domains & IPs:** Always routed through the proxy tunnel.
  - **Block Domains & IPs:** Always dropped/blackholed.
  Tap **Save & Apply Geo Rules** to update routing rules.
- **Geo Database Files (`geoip.dat` & `geosite.dat`):**
  - View live file existence, size (MB), and last modified timestamp for both databases.
  - Choose between **Iran Rules (Chocolate4U)** or **Global Rules (Loyalsoldier)** presets, or specify custom download URLs.
  - Tap **Update Geo Files** to download the latest dat files directly over WAN without disconnecting your existing proxy session.

---

### 7. Per-App Split Tunneling (`Apps` Tab)
Control which Android applications route through Passwall:
- **Filter Modes:**
  - **Bypass Selected Apps:** Proxies all apps except the checked applications (useful for bypassing banking and local streaming apps).
  - **Proxy Only Selected Apps:** Routes all apps direct WAN except the checked applications (useful for tunneling only browsers and messaging apps).
- **Search & Selection:** Filter installed packages by name or UID in real-time and toggle checkboxes.
- Tap **Save & Apply App Rules** to configure iptables UID match chains (`--uid-owner`).
- *Note:* Tethered Wi-Fi Hotspot and USB clients are always proxied regardless of per-app rules.

---

### 8. Base Config Editor & Factory Reset (`Config` Tab)
- **Config Editor:** Directly inspect or modify Xray's `config.json` base template (e.g. adding custom inbounds, socks ports, or custom stream settings). Click **Save & Apply** to validate JSON and restart Xray.
- **Factory Reset:** If a custom configuration causes a crash or failure, tap **Reset to Default** (or run `su -c passwall reset-config` in shell) to restore factory defaults while preserving your saved nodes and subscriptions.

---

### 9. Runtime Logs (`Logs` Tab)
- Real-time output from `xray-core` and the `passwall-droid` background daemon.
- Useful for diagnosing TLS handshake issues, routing decisions, and DNS interception.
- Tap **Clear** to wipe the log buffer.
</details>

## Build & Versioning

```bash
chmod +x build.sh

# Default build (uses module.prop version or v1.2.0, auto versionCode):
./build.sh

# Or pass custom version and versionCode as build arguments:
./build.sh v1.3.0 130

# Or via environment variables:
MOD_VERSION=v1.3.0 MOD_VERSION_CODE=130 ./build.sh
```

When pushing a Git tag (e.g. `git tag v1.2.1 && git push origin v1.2.1`), the GitHub Actions release workflow automatically derives `version` and `versionCode` (e.g. `121`), updates `module.prop`, builds universal ARMv7 & ARM64 binaries along with `XTLS/Xray-core` and `Chocolate4U/Iran-v2ray-rules` (`geoip.dat` & `geosite.dat`), and publishes a new GitHub Release.

## CLI Usage (ADB / Termux)

```bash
su -c passwall status
su -c passwall stop
su -c passwall start
su -c passwall reset-config
su -c passwall update-geo
```

## Author

- **Author:** [Incognito-Coder](https://github.com/Incognito-Coder)
