#!/usr/bin/env bash
# Install intellaro as a systemd service (single-binary POP mode).
# Usage: ./install.sh /path/to/intellaro-binary
set -euo pipefail
BIN="${1:?usage: install.sh /path/to/intellaro-binary}"

id -u intellaro >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin intellaro
install -d -o intellaro -g intellaro /opt/intellaro/bin /etc/intellaro
install -m 0755 "$BIN" /opt/intellaro/bin/intellaro
[ -f /etc/intellaro/config.yaml ] || install -m 0644 "$(dirname "$0")/config.example.yaml" /etc/intellaro/config.yaml
install -m 0644 "$(dirname "$0")/intellaro.service" /etc/systemd/system/intellaro.service
systemctl daemon-reload
systemctl enable --now intellaro
systemctl --no-pager --lines=0 status intellaro
