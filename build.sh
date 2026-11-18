#!/usr/bin/env bash
set -euo pipefail

XRAY_VER="${XRAY_VER:-v26.11.9}"
MOD_VERSION="${MOD_VERSION:-v1.2.0}"
OUT_DIR="dist/passwall-android"
ZIP_NAME="passwall-android-${MOD_VERSION}-universal.zip"

rm -rf dist tmp_dl
mkdir -p "$OUT_DIR/bin/arm" "$OUT_DIR/bin/arm64" "$OUT_DIR/config" tmp_dl

# 1. Cross-compile static passwall-droid binaries (ARMv7 Android 6+ & ARM64)
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUT_DIR/bin/arm/passwall-droid" .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUT_DIR/bin/arm64/passwall-droid" .

# 2. Download official Xray-core ARMv7 & ARM64 binaries
curl -fL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-arm32-v7a.zip" -o tmp_dl/arm.zip
curl -fL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-android-arm64-v8a.zip" -o tmp_dl/arm64.zip

unzip -j tmp_dl/arm.zip xray -d tmp_dl/arm_ext
mv tmp_dl/arm_ext/xray "$OUT_DIR/bin/arm/xray"

unzip -j tmp_dl/arm64.zip xray -d tmp_dl/arm64_ext
mv tmp_dl/arm64_ext/xray "$OUT_DIR/bin/arm64/xray"

# 3. Download enhanced Iran/CN/AdBlock geoip.dat & geosite.dat rulesets
curl -fL "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat" -o "$OUT_DIR/config/geoip.dat"
curl -fL "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat" -o "$OUT_DIR/config/geosite.dat"

# 4. Copy Magisk/KernelSU module scripts and base configuration
cp -r module/* "$OUT_DIR/"
sed -i "s/^version=.*/version=${MOD_VERSION}/" "$OUT_DIR/module.prop"

(cd "$OUT_DIR" && zip -r9 "../../${ZIP_NAME}" .)
rm -rf tmp_dl
echo "Built ${ZIP_NAME} (Xray ${XRAY_VER}) successfully."
