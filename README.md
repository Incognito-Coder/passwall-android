# Passwall Android (Magisk / KernelSU Transparent Proxy)

OpenWrt Passwall-style transparent proxy module for Android 6.0 through Android 16 (`armeabi-v7a` and `arm64-v8a`), powered by `xray-core` and an embedded ES5 web dashboard.

> **Project Origin & Disclaimer:**  
> The name and concept of this project were inspired by OpenWrt's **Passwall** transparent proxy tool. However, this project is completely separate and independent from OpenWrt Passwall's source code—it was designed, engineered, and written from scratch in Go specifically for Android, Magisk, and KernelSU environments.

## Features

- **System-Wide & Hotspot/NAT Transparent Proxy:** Captures local apps (`OUTPUT`) and Wi-Fi hotspot / USB tethering clients (`PREROUTING`) across all interfaces (`wlan0`, `ap0`, `swlan0`, `rndis0`).
- **Android 6.0+ & ARMv7 Compatibility:** Automatically detects kernel `xt_TPROXY` support at startup and falls back to `nat REDIRECT` on legacy Android 6 vendor kernels, with `GOGC=40` and `GOMEMLIMIT=48MiB` memory tuning.
- **Android 12+ eBPF Offload Bypass & Netd Watchdog:** Disables `tether_offload_disabled` so hotspot traffic traverses Netfilter, and restores rules if Android resets tables during network switches.
- **Embedded Web Control Panel (`http://127.0.0.1:9090`):**
  - Switch routing modes (`Rule`, `Global`, `Direct`).
  - Import `vless://` (including `xhttp`, `ws`, `grpc`, `tls`, `reality`), `trojan://`, `vmess://`, `ss://`, and `hysteria2://` / `hy2://` links.
  - Fetch Base64/plain subscription URLs over direct WAN (`SO_MARK 0x02000000`) with optional SSL/TLS certificate verification bypass and scheduled background auto-updates.
  - Concurrent TCP/TLS latency tester with one-tap **Fastest** node selection.
  - Per-app UID split tunneling (`Bypass Selected` or `Proxy Only Selected`) while keeping hotspot clients proxied.

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
```

## Author

- **Author:** [Incognito-Coder](https://github.com/Incognito-Coder)
