#!/system/bin/sh
MODDIR=${0%/*}
"$MODDIR/bin/passwall-droid" stop
rm -f /data/adb/passwall-android.log
