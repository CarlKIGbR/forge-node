# Owner-guide dry-run harness image (N5-prep rework 2): an Ubuntu 24.04 "host" (git 2.43, sudo, OpenSSH, e2fsprogs) with stubs for everything that needs a real network, systemd, Docker, iptables or a hub.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends sudo git openssh-client openssl python3 e2fsprogs iproute2 procps less util-linux tar gzip ca-certificates findutils diffutils \
    && rm -rf /var/lib/apt/lists/*
COPY stubs/ /usr/local/bin/
RUN chmod 0755 /usr/local/bin/* && mv /usr/local/bin/systemctl /usr/bin/systemctl && cp /usr/local/bin/journalctl /usr/bin/journalctl && cp /usr/local/bin/systemd-run /usr/bin/systemd-run \
    && mv /usr/bin/openssl /usr/bin/openssl.real \
    && rm /usr/bin/python3 && mv /usr/local/bin/python3-wrapper /usr/bin/python3
COPY units/ /opt/harness-units/
COPY run_guide.py /opt/run_guide.py
ENTRYPOINT ["python3", "/opt/run_guide.py"]
