# Debian 12 + systemd image used by the Phase 1 integration test.
#
# Why systemd in a container: the install path xray-aio drives writes
# systemd unit files and runs `systemctl enable --now`. Faking that
# would defeat the purpose of integration coverage. With --privileged
# and PID-1 systemd, the container behaves like a real Debian 12 host
# from the orchestrator's perspective.
#
# Boots `/lib/systemd/systemd`. The integration script runs as a
# `systemd-run --wait --pty` job after the system reaches multi-user.
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv \
        ca-certificates curl jq \
    && rm -rf /var/lib/apt/lists/* \
    && find /etc/systemd/system /lib/systemd/system \
        -path '*/wants/*' \
        \( -name '*.mount' -o -name '*udev*' -o -name '*initctl*' \
           -o -name 'systemd-tmpfiles-setup*' \
           -o -name 'systemd-update-utmp*' \
           -o -name 'systemd-firstboot.service' \
           -o -name 'systemd-machine-id-commit.service' \) \
        -delete

# The integration runner copies the just-built binary into the image
# right before `docker build`, so this path needs to exist.
COPY xray-aio /usr/local/bin/xray-aio
COPY run-inside.sh /run-inside.sh
RUN chmod +x /usr/local/bin/xray-aio /run-inside.sh

# systemd convention.
STOPSIGNAL SIGRTMIN+3

CMD ["/lib/systemd/systemd"]
