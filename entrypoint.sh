#!/bin/sh
set -e

# Runs its own D-Bus + bluetoothd, for hosts that have neither (see the
# Dockerfile). Needs --net=host --privileged.
#
# Optional, for kernels without Bluetooth support built in (e.g. Xpenology,
# see github.com/faraga1/xpenology-bt-epyc7002): mount a directory of
# out-of-tree Bluetooth modules at /bt-modules and they get loaded here when
# hci0 is missing -- e.g. after a reboot. Loading them from the container
# that needs them avoids any boot-ordering problems on the host.

BT_MODULES="ecc ecdh_generic bluetooth btintel btbcm btrtl btusb bnep hidp rfcomm"

if [ ! -e /sys/class/bluetooth/hci0 ] && [ -d /bt-modules ]; then
  echo "hci0 missing, loading Bluetooth kernel modules from /bt-modules..."
  for m in $BT_MODULES; do
    if grep -q "^$m " /proc/modules; then
      continue
    fi
    if [ -f "/bt-modules/$m.ko" ]; then
      insmod "/bt-modules/$m.ko" && echo "  loaded $m" || echo "  WARNING: could not load $m"
    fi
  done
fi

echo "Waiting for hci0..."
for i in $(seq 1 30); do
  if [ -e /sys/class/bluetooth/hci0 ]; then
    echo "hci0 found."
    break
  fi
  sleep 2
done
if [ ! -e /sys/class/bluetooth/hci0 ]; then
  # Exiting lets Docker's restart policy retry the whole thing, instead of
  # running a reader that can never scan.
  echo "ERROR: no hci0 after 60s -- is a Bluetooth adapter present (and passed through, in a VM)?"
  exit 1
fi

mkdir -p /run/dbus
rm -f /run/dbus/pid
dbus-daemon --system --fork

BLUETOOTHD=$(command -v bluetoothd || echo /usr/libexec/bluetooth/bluetoothd)
"$BLUETOOTHD" &
sleep 2

bluetoothctl power on || echo "WARNING: could not power on hci0"

exec python3 scale_reader.py
