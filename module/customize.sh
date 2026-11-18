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

mkdir -p "$MODPATH/system/bin"
cat << 'CLI' > "$MODPATH/system/bin/passwall"
#!/system/bin/sh
exec /data/adb/modules/passwall-android/bin/passwall-droid "$@"
CLI

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/passwall-droid" 0 0 0755
set_perm "$MODPATH/bin/xray" 0 0 0755
set_perm "$MODPATH/system/bin/passwall" 0 0 0755

ui_print "- Web Control Panel: http://127.0.0.1:9090"
