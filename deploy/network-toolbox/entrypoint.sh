#!/bin/sh
set -eu

mkdir -p /run/dbus
dbus-daemon --system --fork --nopidfile
mkdir -p /run/avahi-daemon
# Keep Avahi in the foreground as PID 1. Its daemonize handshake is unreliable
# in a read-only container and caused the toolbox to exit and restart.
exec avahi-daemon --no-chroot
