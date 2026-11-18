#!/system/bin/sh
MODDIR=${0%/*}

if "$MODDIR/bin/passwall-droid" status >/dev/null 2>&1; then
    echo "Stopping Passwall Transparent Proxy..."
    "$MODDIR/bin/passwall-droid" stop
else
    echo "Starting Passwall Transparent Proxy..."
    "$MODDIR/bin/passwall-droid" start &
    sleep 1
    "$MODDIR/bin/passwall-droid" status
fi
