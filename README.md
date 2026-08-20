# Snitch

Live per-app outbound connection map for the Omarchy shell: country flags, animated arcs, and one-key per-app firewall blocks.

Coverage is **TCP + connected UDP**. `/proc/net/udp` only has a remote endpoint for `connect()`ed sockets, so most QUIC/HTTP-3 is invisible or listed as `UDP (unresolved)` and **never drawn as an arc**. Reverse-DNS is off. Nothing leaves the machine except the traffic that was already leaving.

## Install

```sh
omarchy plugin add https://github.com/ccdwyer/omarchy-snitch.git --enable
cd ~/.config/omarchy/plugins/io.github.chris.snitch
./build.sh
```

**This repository does not contain Linux binaries.** The authoring host is macOS and cannot emit trustworthy musl/ELF images. First install builds `snitchd` and `snitch-block` from source with one command (`./build.sh`, typically seconds with a warm Cargo cache).

After a git tag, GitHub Actions (`.github/workflows/release.yml`) publishes `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` binaries plus `SHA256SUMS-*`. You can download those release artifacts instead of compiling:

```sh
# example once a v1.x tag exists
arch=x86_64-unknown-linux-musl
ver=v1.0.0
base="https://github.com/<owner>/<repo>/releases/download/${ver}"
curl -LO "${base}/snitchd-${arch}"
curl -LO "${base}/snitch-block-${arch}"
curl -LO "${base}/SHA256SUMS-${arch}"
sha256sum -c "SHA256SUMS-${arch}"
mkdir -p bin
install -m 0755 "snitchd-${arch}" bin/snitchd
install -m 0755 "snitch-block-${arch}" bin/snitch-block
```

`omarchy plugin add` copies files only — it never compiles or installs polkit policy. Monitoring works with zero privilege once `snitchd` is on `PATH` or `./bin/snitchd`. It does **not** need nftables, conntrack, or cgroup v2.

### Required packages (blocking only)

Blocking additionally needs:

| Need | Binary / check | Package (Arch) | Package (Debian/Ubuntu) |
|------|----------------|----------------|-------------------------|
| nftables | `nft` | `nftables` | `nftables` |
| conntrack | `conntrack` | `conntrack-tools` | `conntrack-tools` |
| cgroup v2 | `/sys/fs/cgroup/cgroup.controllers` | kernel unified hierarchy (systemd default) | same |

```sh
# Omarchy / Arch
sudo pacman -S nftables conntrack-tools
```

`snitch-block status` reports `nft`, `conntrack`, `cgroupv2`, and `blockingReady`. If any are missing, the UI greys out block controls and shows the reason plus the package names. The map keeps running.

Blocking needs the helper installed at the path the polkit policy authorizes. Open the Snitch panel from the bar and click **Install helper** — that opens a terminal in the plugin directory, builds `snitch-block` if needed, and runs `scripts/install-privileged.sh`. Enter your password in the polkit prompt (setup may ask twice: copy files, then authorize the helper). After that, blocks should be prompt-free.

The same panel has **Build snitchd** when the daemon is missing and **Install packages** when `nftables` / `conntrack-tools` are missing.

You can still run the script by hand from the plugin directory:

```sh
cd ~/.config/omarchy/plugins/io.github.chris.snitch
./scripts/install-privileged.sh
```

That script copies the helper with `pkexec /usr/bin/install` (not `pkexec bash`), then runs `pkexec /usr/lib/snitch/snitch-block status` so **the path-scoped helper action** is what `auth_admin_keep` caches. Do not use `sudo`.

Place the pill if it did not land on the bar:

```sh
omarchy bar move io.github.chris.snitch --section right
```

## Usage

Click the bar pill (live connection count) to open the panel.

- **Quiet pill** — count of live conversations
- **Amber pulse** — a network prefix never seen before (/24 v4, /48 v6)
- **Red outline** — at least one app is blocked
- Away digest on open: `N new networks while you were away`

Hover an arc: `firefox → 142.250.x.x, US, port 443`.

### Keybinds (panel focused)

| Key | Action |
|-----|--------|
| `↑` `↓` / `k` `j` | Move the app list |
| `b` / Enter | Block or unblock the selected app |
| `i` | Install helper, build snitchd, or install nftables (when shown) |
| `/` | Search apps, IPs, countries |
| Esc | Close search, confirm dialog, or panel |

The supported way to open the panel is **clicking the bar pill** (or the bar-widget `open()`/`toggle()` the shell routes to that widget). The manifest also declares a `panel` kind so `shell summon|hide|toggle|call` are valid IPC verbs:

```sh
omarchy-shell shell summon io.github.chris.snitch '{}'
omarchy-shell shell hide io.github.chris.snitch
omarchy-shell shell toggle io.github.chris.snitch '{}'
omarchy-shell shell call io.github.chris.snitch ping '{}'
```

`shell call … ping` works when the panel is loaded (`keepLoaded`). The reliable service path is the keep-loaded IpcHandler (always pass the string argument):

```sh
omarchy-shell io.github.chris.snitch ping ''
omarchy-shell io.github.chris.snitch status ''
```

Summoned placement is best-effort (`KeyboardPanel` `centerOnBar` when the host provides `shell.bar`). That host field is not in the Quattro IPC table; if it is missing, use the pill.

## Blocking

**Blocking uses nftables via polkit.** Monitoring does not. Production blocks always run `pkexec /usr/lib/snitch/snitch-block` — checkout copies are never authorized.

`block-app` creates `/sys/fs/cgroup/snitch.slice/snitch-<app>/`, migrates the app's process tree into it, installs

```
socket cgroupv2 level N "snitch.slice/snitch-<app>" drop
```

on `table inet snitch` (`N` is the path-component count, 2 for the default layout), migrates **every live PID** in the validated forest (including same-UID helpers in a private `app-*.scope`), and flushes conntrack for TCP **and** connected UDP remotes. `verified: true` is returned only when every live PID is in the snitch cgroup, the nft rule lists, **and** conntrack deletion succeeded. Processes already in the root cgroup are refused (endpoint fallback is offered). Partial migration rolls back.

If cgroup migration or the match fails, the UI offers **endpoints only — affects all apps** and will not silently substitute `block-ips`. Endpoint fallback records per-app ownership; **Unblock** calls `unblock-ips` so that app's addresses leave the set (shared addresses owned by another blocked app stay). `system` and `unknown` rows cannot be blocked.

If no polkit authentication agent is present, `/usr/lib/snitch/snitch-block` is missing, or `nft` / `conntrack` / cgroup v2 is unavailable, block controls are greyed and the panel shows the reason. Monitoring still works.

`snitch-block teardown` deletes `table inet snitch` and the plugin's cgroups and reports failure if either remains. Other firewall tables are never touched.

## Honest limitations

- Sub-second flows can slip between 500ms samples. The seen-set is advisory.
- TIME_WAIT and LISTEN sockets are parsed then dropped; they are not conversations.
- Other-uid processes appear as **system** (no desktop identity without privilege) and cannot be blocked.
- UDP remotes via conntrack are a documented v1.1 path, not a 1.0 claim.
- Linux prebuilts are **not** committed. First install is `./build.sh`. Tagged GitHub Releases from CI carry musl binaries and checksums.
- City-level geo is out of scope. Centroids are country-level.

## Replay / fallback

```sh
./bin/snitchd --replay tests/fixtures/replay.ndjson --socket "$XDG_RUNTIME_DIR/snitch.sock"
```

If `snitchd` is missing, the service plays `data/replay.ndjson` inside QML so the map still opens.

## Dev

```sh
./tests/run.sh          # cargo test + node model tests + snitchd --self-test
cargo test --workspace
```

QML hot-reloads from `~/.config/omarchy/plugins/io.github.chris.snitch/`.

## Attribution

- IP geolocation by [DB-IP](https://db-ip.com) Country Lite, [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
- Landmass: [Natural Earth](https://www.naturalearthdata.com/) 110m, public domain.
- Flags: bundled geometric SVGs (no emoji-font dependence); ISO code fallback.

## Remove

```sh
omarchy plugin remove io.github.chris.snitch
pkexec /usr/lib/snitch/snitch-block teardown
pkexec rm -f /usr/lib/snitch/snitch-block /usr/share/polkit-1/actions/io.github.chris.snitch.policy
```
