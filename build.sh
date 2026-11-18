#!/usr/bin/env bash
set -euo pipefail

# Allow passing version, versionCode, and xray version via args or env:
# Usage: ./build.sh [MOD_VERSION] [MOD_VERSION_CODE] [XRAY_VER]
MOD_VERSION="${1:-${MOD_VERSION:-v1.2.3}}"
MOD_VERSION_CODE="${2:-${MOD_VERSION_CODE:-}}"
XRAY_VER="${3:-${XRAY_VER:-v26.11.9}}"

if [ -z "${MOD_VERSION_CODE}" ]; then
  if [[ "${MOD_VERSION}" =~ ^v?([0-9]+)\.([0-9]+)(\.([0-9]+))? ]]; then
    MAJOR="${BASH_REMATCH[1]}"
    MINOR="${BASH_REMATCH[2]}"
    PATCH="${BASH_REMATCH[4]:-0}"
    MOD_VERSION_CODE=$(( 10#$MAJOR * 100 + 10#$MINOR * 10 + 10#$PATCH ))
  else
    MOD_VERSION_CODE=$(grep -E '^versionCode=' module/module.prop 2>/dev/null | cut -d= -f2 || echo 120)
  fi
fi

OUT_DIR="dist/passwall-android"
ZIP_NAME="passwall-android-${MOD_VERSION}-universal.zip"
CACHE_DIR=".cache/downloads/${XRAY_VER}"

echo "Building Passwall Android version: ${MOD_VERSION} (versionCode: ${MOD_VERSION_CODE}, author: Incognito-Coder)"

rm -rf dist
rm -f "${ZIP_NAME}" "${ZIP_NAME}.sha256"
mkdir -p "$OUT_DIR/bin/arm" "$OUT_DIR/bin/arm64" "$OUT_DIR/config" "${CACHE_DIR}/arm" "${CACHE_DIR}/arm64" .cache/downloads

# 1. Cross-compile static passwall-droid binaries (ARMv7 Android 6+ & ARM64)
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -ldflags="-s -w -X main.AppVersion=${MOD_VERSION}" -o "$OUT_DIR/bin/arm/passwall-droid" .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.AppVersion=${MOD_VERSION}" -o "$OUT_DIR/bin/arm64/passwall-droid" .

# 2. Download official Xray-core ARMv7 & ARM64 binaries (with local caching)
if [ ! -f "${CACHE_DIR}/arm/xray" ]; then
  echo "Downloading Xray ARMv7 (${XRAY_VER})..."
  mkdir -p tmp_dl
  curl -fL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-arm32-v7a.zip" -o tmp_dl/arm.zip
  unzip -jo tmp_dl/arm.zip xray -d "${CACHE_DIR}/arm"
  rm -f tmp_dl/arm.zip
fi

if [ ! -f "${CACHE_DIR}/arm64/xray" ]; then
  echo "Downloading Xray ARM64 (${XRAY_VER})..."
  mkdir -p tmp_dl
  curl -fL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-android-arm64-v8a.zip" -o tmp_dl/arm64.zip
  unzip -jo tmp_dl/arm64.zip xray -d "${CACHE_DIR}/arm64"
  rm -f tmp_dl/arm64.zip
fi

cp "${CACHE_DIR}/arm/xray" "$OUT_DIR/bin/arm/xray"
cp "${CACHE_DIR}/arm64/xray" "$OUT_DIR/bin/arm64/xray"

# 3. Download enhanced Iran/CN/AdBlock geoip.dat & geosite.dat rulesets (with local caching)
if [ ! -f ".cache/downloads/geoip.dat" ]; then
  echo "Downloading geoip.dat ruleset..."
  curl -fL "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat" -o ".cache/downloads/geoip.dat"
fi

if [ ! -f ".cache/downloads/geosite.dat" ]; then
  echo "Downloading geosite.dat ruleset..."
  curl -fL "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat" -o ".cache/downloads/geosite.dat"
fi

# Single copy in bin/ alongside the xray binary to prevent duplicate asset inflation
cp ".cache/downloads/geoip.dat" "$OUT_DIR/bin/geoip.dat"
cp ".cache/downloads/geosite.dat" "$OUT_DIR/bin/geosite.dat"

# 4. Copy Magisk/KernelSU module scripts and base configuration
cp -r module/* "$OUT_DIR/"
sed -i "s/^version=.*/version=${MOD_VERSION}/" "$OUT_DIR/module.prop"
sed -i "s/^versionCode=.*/versionCode=${MOD_VERSION_CODE}/" "$OUT_DIR/module.prop"
sed -i "s/^author=.*/author=Incognito-Coder/" "$OUT_DIR/module.prop"

# Also sync source module.prop if present
if [ -f "module/module.prop" ]; then
  sed -i "s/^version=.*/version=${MOD_VERSION}/" module/module.prop
  sed -i "s/^versionCode=.*/versionCode=${MOD_VERSION_CODE}/" module/module.prop
  sed -i "s/^author=.*/author=Incognito-Coder/" module/module.prop
fi

(cd "$OUT_DIR" && zip -r9 "../../${ZIP_NAME}" .)
echo "Built ${ZIP_NAME} (Xray ${XRAY_VER}, version ${MOD_VERSION}, versionCode ${MOD_VERSION_CODE}) successfully."
