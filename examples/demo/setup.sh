#!/usr/bin/env bash
# Install or remove the demo service used by the README and the live tests. Run as root on a machine with systemd.
#
#   sudo examples/demo/setup.sh up     # install and start sdh-demo.service (its unit lives under /run, so a reboot removes it)
#   sudo examples/demo/setup.sh down   # stop it and remove everything
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
unit=sdh-demo.service
lib=/usr/local/lib/systemd-harden-demo
unit_file="/run/systemd/system/${unit}"

[ "$(id -u)" -eq 0 ] || {
  echo "setup.sh: run it as root" >&2
  exit 2
}
[ -d /run/systemd/system ] || {
  echo "setup.sh: systemd is not the running init system here" >&2
  exit 2
}

case "${1:-}" in
  up)
    install -D -m 0755 "${here}/service.py" "${lib}/service.py"
    install -d /home/sdh-demo /var/lib/sdh-demo
    echo hello > /home/sdh-demo/data
    install -D -m 0644 "${here}/demo.service" "${unit_file}"
    systemctl daemon-reload
    systemctl start "${unit}"
    for _ in $(seq 1 50); do
      if python3 "${lib}/service.py" check ping --port 18765 > /dev/null 2>&1; then
        echo "${unit} is running; check it with: python3 ${lib}/service.py check tmp,home,var"
        exit 0
      fi
      sleep 0.2
    done
    echo "setup.sh: ${unit} did not come up" >&2
    systemctl status "${unit}" --no-pager >&2 || true
    exit 1
    ;;
  down)
    systemctl stop "${unit}" 2> /dev/null || true
    rm -f "${unit_file}"
    rm -rf "${lib}" /home/sdh-demo /var/lib/sdh-demo "/run/systemd/system/${unit}.d"
    systemctl daemon-reload
    echo "${unit} removed"
    ;;
  *)
    echo "usage: setup.sh up|down" >&2
    exit 2
    ;;
esac
