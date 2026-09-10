#!/bin/sh
set -eu

mkdir -p /run/dbus
dbus-daemon --system --fork --nopidfile
mkdir -p /run/avahi-daemon
avahi-daemon --daemonize --no-chroot
avahi-daemon --check

exec sleep infinity
