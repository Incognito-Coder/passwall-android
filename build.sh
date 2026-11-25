#!/usr/bin/env bash
set -euo pipefail

# Allow passing version, versionCode, xray version, and build target via args or env:
# Usage: ./build.sh [MOD_VERSION] [MOD_VERSION_CODE] [XRAY_VER] [BUILD_TARGET]
# BUILD_TARGET: all (default: universal + arm64-v8a + armeabi-v7a), universal, arm64-v8a, armeabi-v7a
MOD_VERSION="${1:-${MOD_VERSION:-v1.2.6}}"
MOD_VERSION_CODE="${2:-${MOD_VERSION_CODE:-}}"
XRAY_VER="${3:-${XRAY_VER:-v26.11.9}}"
BUILD_TARGET="${4:-${BUILD_TARGET:-all}}"

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

case "${BUILD_TARGET}" in
  all)
    NEED_ARM=true
    NEED_ARM64=true
    PACKAGE_TARGETS=("universal" "arm64-v8a" "armeabi-v7a")
    ;;
  universal)
    NEED_ARM=true
    NEED_ARM64=true
    PACKAGE_TARGETS=("universal")
    ;;
  arm64|arm64-v8a)
    NEED_ARM=false
    NEED_ARM64=true
    PACKAGE_TARGETS=("arm64-v8a")
    ;;
  arm|armv7|armeabi-v7a)
    NEED_ARM=true
    NEED_ARM64=false
    PACKAGE_TARGETS=("armeabi-v7a")
    ;;
  *)
    echo "Unsupported BUILD_TARGET '${BUILD_TARGET}' (expected: all, universal, arm64-v8a, armeabi-v7a)" >&2
    exit 1
    ;;
esac

CACHE_DIR=".cache/downloads/${XRAY_VER}"
COMMON_DIR="dist/common"

echo "Building Passwall Android version: ${MOD_VERSION} (versionCode: ${MOD_VERSION_CODE}, target: ${BUILD_TARGET}, author: Incognito-Coder)"

rm -rf dist tmp_dl
rm -f "passwall-android-${MOD_VERSION}-"*.zip "passwall-android-${MOD_VERSION}-"*.zip.sha256
mkdir -p "$COMMON_DIR/bin" "$COMMON_DIR/config" "${CACHE_DIR}/arm" "${CACHE_DIR}/arm64" .cache/downloads

update_module_prop() {
  local prop_file="$1"
  sed -e "s/^version=.*/version=${MOD_VERSION}/" \
      -e "s/^versionCode=.*/versionCode=${MOD_VERSION_CODE}/" \
      -e "s/^author=.*/author=Incognito-Coder/" \
      "$prop_file" > "${prop_file}.tmp" && mv "${prop_file}.tmp" "$prop_file"
}

prepare_arch() {
  local arch_dir="$1"
  local goarch="$2"
  local goarm="$3"
  local xray_asset="$4"
  local out_arch_dir="dist/arch/${arch_dir}"

  mkdir -p "$out_arch_dir"

  # 1. Cross-compile static passwall-droid binary
  if [ -n "$goarm" ]; then
    GOOS=linux GOARCH="$goarch" GOARM="$goarm" CGO_ENABLED=0 \
      go build -ldflags="-s -w -X main.AppVersion=${MOD_VERSION}" -o "$out_arch_dir/passwall-droid" .
  else
    GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 \
      go build -ldflags="-s -w -X main.AppVersion=${MOD_VERSION}" -o "$out_arch_dir/passwall-droid" .
  fi

  # 2. Download official Xray-core binary (with local caching)
  if [ ! -f "${CACHE_DIR}/${arch_dir}/xray" ]; then
    echo "Downloading Xray ${arch_dir} (${XRAY_VER})..."
    mkdir -p tmp_dl
    curl -fL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/${xray_asset}" -o "tmp_dl/${arch_dir}.zip"
    unzip -jo "tmp_dl/${arch_dir}.zip" xray -d "${CACHE_DIR}/${arch_dir}"
    rm -f "tmp_dl/${arch_dir}.zip"
  fi
  cp "${CACHE_DIR}/${arch_dir}/xray" "$out_arch_dir/xray"
}

# Prepare architecture binaries as needed
if [ "$NEED_ARM" = true ]; then
  prepare_arch "arm" "arm" "7" "Xray-linux-arm32-v7a.zip"
fi
if [ "$NEED_ARM64" = true ]; then
  prepare_arch "arm64" "arm64" "" "Xray-android-arm64-v8a.zip"
fi
rm -rf tmp_dl

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
cp ".cache/downloads/geoip.dat" "$COMMON_DIR/bin/geoip.dat"
cp ".cache/downloads/geosite.dat" "$COMMON_DIR/bin/geosite.dat"

# 4. Copy Magisk/KernelSU module scripts and base configuration into shared staging
cp -pR module/* "$COMMON_DIR/"
update_module_prop "$COMMON_DIR/module.prop"

# Also sync source module.prop if present
if [ -f "module/module.prop" ]; then
  update_module_prop "module/module.prop"
fi

package_target() {
  local target="$1"
  local stage_dir="dist/pkg-${target}"
  local zip_name="passwall-android-${MOD_VERSION}-${target}.zip"

  mkdir -p "$stage_dir"
  cp -pR "$COMMON_DIR/." "$stage_dir/"

  if [ "$target" = "universal" ] || [ "$target" = "armeabi-v7a" ]; then
    mkdir -p "$stage_dir/bin/arm"
    cp -pR dist/arch/arm/. "$stage_dir/bin/arm/"
  fi
  if [ "$target" = "universal" ] || [ "$target" = "arm64-v8a" ]; then
    mkdir -p "$stage_dir/bin/arm64"
    cp -pR dist/arch/arm64/. "$stage_dir/bin/arm64/"
  fi

  (cd "$stage_dir" && zip -r9 "../../${zip_name}" .)
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${zip_name}" > "${zip_name}.sha256"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${zip_name}" > "${zip_name}.sha256"
  fi
  echo "Built ${zip_name} (Xray ${XRAY_VER}, version ${MOD_VERSION}, versionCode ${MOD_VERSION_CODE}) successfully."
}

for t in "${PACKAGE_TARGETS[@]}"; do
  package_target "$t"
done
