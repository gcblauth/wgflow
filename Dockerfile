FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# WireGuard userland + iptables + python. We rely on the kernel module on the
# host; we only need the tools in the container.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        iproute2 \
        iptables \
        iputils-ping \
        conntrack \
        dnsmasq \
        procps \
        ca-certificates \
        curl \
        python3 \
        python3-pip \
        python3-venv \
        qrencode \
        tini \
        mtr-tiny \
        traceroute \
        dnsutils \
        iperf3 \
    && rm -rf /var/lib/apt/lists/*

# Disable the system dnsmasq service - we run it manually from entrypoint.sh
# so we control the lifecycle and can pass our own config path. The Debian
# package enables it by default which would fight us at boot.
RUN systemctl disable dnsmasq 2>/dev/null || true

# Fetch the StevenBlack unified hosts list at build time. We bake it into
# the image so first boot doesn't depend on internet egress. Operators can
# replace it at runtime via a volume mount on /etc/dnsmasq.d/blocklist.hosts
# if they want a fresher copy or a different list.
RUN mkdir -p /etc/dnsmasq.d \
 && curl -fsSL https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
        -o /etc/dnsmasq.d/blocklist.hosts \
 && echo "[wgflow build] fetched $(wc -l < /etc/dnsmasq.d/blocklist.hosts) blocklist entries"

# Prefer legacy iptables binaries. The nftables backend shipped in Debian
# bookworm does not always cooperate with older host kernels; legacy is the
# lowest common denominator and matches what most WireGuard tutorials assume.
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy \
 && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

WORKDIR /srv

# Install python deps in an isolated venv so we do not fight the system
# "externally managed environment" marker on Debian.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY app/requirements.txt /srv/app/requirements.txt
RUN pip install -r /srv/app/requirements.txt

COPY app /srv/app
COPY dnsmasq.conf.template /etc/dnsmasq.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 51820/udp = wireguard, 8080/tcp = admin API (bound to localhost in compose)
EXPOSE 51820/udp
EXPOSE 8080/tcp

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
