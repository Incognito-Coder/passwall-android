#!/system/bin/sh
SKIPUNZIP=0

ui_print "- Detecting device CPU architecture: $ARCH"

case "$ARCH" in
  arm)
    ui_print "- Installing ARMv7 (armeabi-v7a) binaries for Android 6+"
    cp -f "$MODPATH/bin/arm/passwall-droid" "$MODPATH/bin/passwall-droid"
    cp -f "$MODPATH/bin/arm/xray" "$MODPATH/bin/xray"
    ;;
  arm64)
    ui_print "- Installing ARM64 (arm64-v8a) binaries"
    cp -f "$MODPATH/bin/arm64/passwall-droid" "$MODPATH/bin/passwall-droid"
    cp -f "$MODPATH/bin/arm64/xray" "$MODPATH/bin/xray"
    ;;
  *)
    abort "! Unsupported architecture: $ARCH (requires arm or arm64)"
    ;;
esac

rm -rf "$MODPATH/bin/arm" "$MODPATH/bin/arm64"

# --------------------------------------------------------------------------
# Preserve user configuration (config.json) & UI state (state.json)
# --------------------------------------------------------------------------
OLD_MOD="/data/adb/modules/passwall-android"
PERSIST_DIR="/data/adb/passwall"
mkdir -p "$PERSIST_DIR"
mkdir -p "$MODPATH/config"

# 1. Preserve or restore state.json (UI state: nodes, subscriptions, DNS, app split tunneling)
if [ -f "$OLD_MOD/config/state.json" ]; then
  ui_print "- Preserving existing UI configuration (nodes, subscriptions, DNS, apps)"
  cp -f "$OLD_MOD/config/state.json" "$MODPATH/config/state.json"
  cp -f "$OLD_MOD/config/state.json" "$PERSIST_DIR/state.json"
elif [ -f "$PERSIST_DIR/state.json" ]; then
  ui_print "- Restoring UI configuration from persistent storage"
  cp -f "$PERSIST_DIR/state.json" "$MODPATH/config/state.json"
fi

# 2. Preserve or restore config.json (Base Xray core configuration)
if [ -f "$OLD_MOD/config/config.json" ]; then
  ui_print "- Preserving existing base Xray config (config.json)"
  cp -f "$OLD_MOD/config/config.json" "$MODPATH/config/config.json"
  cp -f "$OLD_MOD/config/config.json" "$PERSIST_DIR/config.json"
elif [ -f "$PERSIST_DIR/config.json" ]; then
  ui_print "- Restoring base Xray config from persistent storage"
  cp -f "$PERSIST_DIR/config/config.json" "$MODPATH/config/config.json"
else
  # Fresh installation: initialize persistent backup
  cp -f "$MODPATH/config/config.json" "$PERSIST_DIR/config.json"
fi

# --------------------------------------------------------------------------
# Setup geoip.dat and geosite.dat ruleset symlinks
# --------------------------------------------------------------------------
# Clean legacy duplicate files in config/ and module root, then symlink to bin/
rm -f "$MODPATH/config/geoip.dat" "$MODPATH/config/geosite.dat"
rm -f "$MODPATH/geoip.dat" "$MODPATH/geosite.dat"
ln -sf "$MODPATH/bin/geoip.dat" "$MODPATH/config/geoip.dat"
ln -sf "$MODPATH/bin/geosite.dat" "$MODPATH/config/geosite.dat"
ln -sf "$MODPATH/bin/geoip.dat" "$MODPATH/geoip.dat"
ln -sf "$MODPATH/bin/geosite.dat" "$MODPATH/geosite.dat"

mkdir -p "$MODPATH/system/bin"
cat << 'CLI' > "$MODPATH/system/bin/passwall"
#!/system/bin/sh
exec /data/adb/modules/passwall-android/bin/passwall-droid "$@"
CLI

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$PERSIST_DIR" 0 0 0755 0644
set_perm "$MODPATH/bin/passwall-droid" 0 0 0755
set_perm "$MODPATH/bin/xray" 0 0 0755
set_perm "$MODPATH/system/bin/passwall" 0 0 0755

ui_print "- Web Control Panel: http://127.0.0.1:9090 (or http://<device-ip>:9090)"
