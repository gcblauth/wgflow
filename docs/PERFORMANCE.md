# wgflow — Host Performance Tuning

WireGuard's data plane runs in the **host kernel**, not in the wgflow
container. So the optimizations that raise WireGuard throughput are
**host-side** — wgflow itself can't apply them from inside its
container. This document covers them.

For most installs the defaults are fine. Reach for this when you're
pushing serious throughput (hundreds of Mbps to multi-Gbps) and want
to remove the host as the bottleneck.

---

## The quick way

The repo ships a script that applies everything below, persistently
across reboots, with autodetection and a revert option:

```bash
sudo ./scripts/host-tune.sh            # sysctl + NIC offloads
sudo ./scripts/host-tune.sh --governor # also pin the CPU governor
sudo ./scripts/host-tune.sh --dry-run  # preview, change nothing
sudo ./scripts/host-tune.sh --revert   # undo everything
```

It runs on the **host**, not in the container. It is opt-in, asks for
confirmation, and is fully reversible. The rest of this document
explains what it does and why, for operators who want to apply the
pieces by hand or understand the trade-offs.

---

## 1. Socket buffers + netdev backlog (sysctl)

WireGuard moves a lot of UDP. The default Linux socket buffer ceilings
and the per-CPU input queue depth are sized for general workloads; at
high packet rates they can cause drops.

```
# /etc/sysctl.d/99-wireguard.conf
net.core.rmem_max          = 33554432
net.core.wmem_max          = 33554432
net.core.netdev_max_backlog = 250000
```

- `rmem_max` / `wmem_max` — the maximum receive/send socket buffer the
  kernel will grant (bytes). This is a **ceiling**, not an allocation;
  actual buffers are sized by autotuning. 32 MiB is generous without
  being wasteful. Some guides suggest 128 MiB — that's overkill for
  most hosts and a poor idea on low-RAM boxes like a Raspberry Pi.
- `netdev_max_backlog` — how many packets the per-CPU input queue
  holds before dropping, when the NIC delivers faster than the stack
  drains. Higher = more burst tolerance.

These are **host-global** (`net.core.*`) — they are not network-namespace
scoped, so a container, even privileged, cannot set them meaningfully.
They must be set on the host.

A file in `/etc/sysctl.d/` is re-applied by systemd on every boot — no
extra persistence needed. Apply immediately with `sysctl --system`.

---

## 2. NIC hardware offloads (ethtool)

Modern NICs can offload segmentation and aggregation work from the CPU.
For WireGuard the most relevant one is **`rx-udp-gro-forwarding`**: it
lets the NIC coalesce inbound UDP packets before they reach WireGuard,
which on recent kernels measurably raises throughput.

```bash
ethtool -K <nic> tx on sg on tso on gso on gro on rx-udp-gro-forwarding on
```

Two things to know:

- **`rx-udp-gro-forwarding` needs a recent kernel** (roughly 6.x+).
  On older kernels `ethtool` errors on that one flag — apply the
  features individually so one unsupported flag doesn't block the
  rest. (`host-tune.sh` does exactly this.)
- **`ethtool -K` is volatile.** The settings are lost on reboot or when
  the interface is brought down. They need to be re-applied at boot.

### Finding the right NIC

Apply offloads to the **physical interface that carries your traffic**,
not `lo`, `wg0`, `docker0`, or a container veth. Find it with:

```bash
ip route get 8.8.8.8
# 8.8.8.8 via 192.168.1.1 dev enp1s0 src ...
#                         ^^^^^^^^^^ this one
```

If the host uses a **bridge** or **bond**, `ip route get` returns the
bridge/bond name — offloads set there may not propagate to the physical
NICs underneath. In that case apply them to the physical members.

### Making it persist

`ethtool -K` has no portable config file (the mechanism differs across
ifupdown / netplan / NetworkManager). The portable way is a small
systemd unit that re-runs `ethtool` after the network is up:

```ini
# /etc/systemd/system/wgflow-nic-offload.service
[Unit]
Description=wgflow — enable NIC hardware offloads
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=-/usr/sbin/ethtool -K enp1s0 tx on
ExecStart=-/usr/sbin/ethtool -K enp1s0 sg on
ExecStart=-/usr/sbin/ethtool -K enp1s0 tso on
ExecStart=-/usr/sbin/ethtool -K enp1s0 gso on
ExecStart=-/usr/sbin/ethtool -K enp1s0 gro on
ExecStart=-/usr/sbin/ethtool -K enp1s0 rx-udp-gro-forwarding on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

The leading `-` on each `ExecStart` tells systemd to ignore a non-zero
exit, so an unsupported offload is skipped rather than failing the unit.
Replace `enp1s0` with your NIC. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wgflow-nic-offload.service
```

Verify: `ethtool -k <nic> | grep -E 'udp-gro|generic-receive|tcp-segmentation'`.

---

## 3. CPU frequency governor

By default most Linux hosts use the `ondemand` / `schedutil` governor,
which scales CPU frequency with load. The `performance` governor pins
every core at maximum frequency — removing the ramp-up latency when a
traffic burst arrives and raising sustained peak throughput.

```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**Trade-off:** `performance` keeps the CPU at full clock at all times.
That means higher idle power draw and more heat. On a server with
proper cooling this is fine. On a **Raspberry Pi or a fanless mini-PC,
make sure cooling is adequate** before pinning it — sustained max clock
without airflow leads to thermal throttling, which is worse than just
leaving the governor on `ondemand`.

This is why `host-tune.sh` does **not** apply the governor unless you
explicitly pass `--governor`.

`/sys/devices/system/cpu/.../cpufreq/` is hardware state — not
namespace-scoped, so the container cannot touch it. VMs and many cloud
instances don't expose a governor at all.

### Making it persist

Like `ethtool`, the governor resets on reboot. A systemd unit:

```ini
# /etc/systemd/system/wgflow-cpu-governor.service
[Unit]
Description=wgflow — pin CPU scaling governor to performance
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g"; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wgflow-cpu-governor.service
```

---

## What about MSS / MTU?

Those are **not** host-tuning — wgflow handles them itself:

- **MSS clamp** — a network setting in the panel installs an iptables
  `TCPMSS --clamp-mss-to-pmtu` rule on `wg0`, fixing TCP stalls on
  paths where ICMP PMTUD is broken. Toggle it in the panel; it's part
  of wgflow's own iptables reconcile.
- **Client MTU** — per-peer, written as `MTU =` into a peer's generated
  config.

Neither needs `host-tune.sh`. See the panel's network settings.

---

## What NOT to bother with

- **128 MiB socket buffers** — 32 MiB is plenty; larger just reserves
  address space you won't use.
- **Offloads on `wg0`** — the WireGuard interface is virtual; the
  offloads that matter are on the *physical* NIC.
- **Tuning inside the container** — none of the above can be set from
  the container. It all belongs on the host.
