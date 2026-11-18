# Passwall Android (Magisk / KernelSU Transparent Proxy)

OpenWrt Passwall-style transparent proxy module for Android 6.0 through Android 16 (`armeabi-v7a` and `arm64-v8a`), powered by `xray-core` and an embedded ES5 web dashboard.

## Features

- **System-Wide & Hotspot/NAT Transparent Proxy:** Captures local apps (`OUTPUT`) and Wi-Fi hotspot / USB tethering clients (`PREROUTING`) across all interfaces (`wlan0`, `ap0`, `swlan0`, `rndis0`).
- **Android 6.0+ & ARMv7 Compatibility:** Automatically detects kernel `xt_TPROXY` support at startup and falls back to `nat REDIRECT` on legacy Android 6 vendor kernels, with `GOGC=40` and `GOMEMLIMIT=48MiB` memory tuning.
- **Android 12+ eBPF Offload Bypass & Netd Watchdog:** Disables `tether_offload_disabled` so hotspot traffic traverses Netfilter, and restores rules if Android resets tables during network switches.
- **Embedded Web Control Panel (`http://127.0.0.1:9090`):**
  - Switch routing modes (`Rule`, `Global`, `Direct`).
  - Import `vless://` (including `xhttp`, `ws`, `grpc`, `tls`, `reality`), `trojan://`, `vmess://`, and `ss://` links.
  - Fetch Base64/plain subscription URLs over direct WAN (`SO_MARK 0x02000000`) with scheduled background auto-updates.
  - Concurrent TCP/TLS latency tester with one-tap **Fastest** node selection.
  - Per-app UID split tunneling (`Bypass Selected` or `Proxy Only Selected`) while keeping hotspot clients proxied.

## Local Build

```bash
chmod +x build.sh
./build.sh
```

This compiles `passwall-droid` for `arm` (`GOARM=7`) and `arm64`, downloads `XTLS/Xray-core` and `Chocolate4U/Iran-v2ray-rules` (`geoip.dat` & `geosite.dat`), and outputs `passwall-android-v1.2.0-universal.zip`.

## CLI Usage (ADB / Termux)

```bash
su -c passwall status
su -c passwall stop
su -c passwall start
```
