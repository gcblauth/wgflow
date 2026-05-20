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
        tcpdump \
        dnsutils \
        iperf3 \
    && rm -rf /var/lib/apt/lists/*

# Note: the Debian dnsmasq package ships a systemd unit, but this image
# has no init system — dnsmasq only ever runs because entrypoint.sh
# launches it explicitly (and only when WG_LOCAL_DNS=1). There's
# nothing to disable; the package's unit file is simply inert here.

# Fetch the StevenBlack unified hosts list at build time. We bake it into
# the image so first boot doesn't depend on internet egress. Operators can
# replace it at runtime via a volume mount on /etc/dnsmasq.d/blocklist.hosts
# if they want a fresher copy or a different list.
#
# Made non-fatal: if the build host has restricted egress (no internet, no
# proxy, GitHub blocked), we still produce a working image — just with
# an empty blocklist that the panel can populate later from runtime.
# The build log makes the failure visible so operators know to refresh
# the list once the container is up.
RUN mkdir -p /etc/dnsmasq.d \
 && (curl -fsSL --max-time 30 https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
        -o /etc/dnsmasq.d/blocklist.hosts \
     && echo "[wgflow build] fetched $(wc -l < /etc/dnsmasq.d/blocklist.hosts) blocklist entries" \
    ) || (echo "[wgflow build] WARNING: blocklist fetch failed (no internet?). Shipping empty list." \
        && touch /etc/dnsmasq.d/blocklist.hosts)

# Prefer legacy iptables binaries. The nftables backend shipped in Debian
# bookworm does not always cooperate with older host kernels; legacy is the
# lowest common denominator and matches what most WireGuard tutorials assume.
#
# Non-fatal: on some base images / architectures the alternatives may not
# be registered under these exact names, or the legacy binaries may be
# the default already. A failure here shouldn't abort the whole build —
# the entrypoint works with either backend, legacy is just preferred.
RUN (update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null \
     && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null \
     && echo "[wgflow build] iptables set to legacy backend") \
 || echo "[wgflow build] note: could not switch iptables to legacy (may already be, or alternatives unavailable) — continuing"

WORKDIR /srv

# Install python deps in an isolated venv so we do not fight the system
# "externally managed environment" marker on Debian.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY app/requirements.txt /srv/app/requirements.txt
# Upgrade pip first — some ARM wheels (bcrypt, pydantic-core) need a
# recent pip to resolve the right prebuilt wheel instead of trying
# to compile from source (which would need a toolchain we don't ship).
RUN pip install --upgrade pip \
 && pip install -r /srv/app/requirements.txt

COPY app /srv/app
COPY dnsmasq.conf.template /etc/dnsmasq.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 51820/udp = wireguard, 8080/tcp = admin API (bound to localhost in compose)
EXPOSE 51820/udp
EXPOSE 8080/tcp

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
