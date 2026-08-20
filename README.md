# Snitch

Live per-app outbound connection map for the Omarchy shell: country flags, animated arcs, and one-key per-app firewall blocks.

Coverage is **TCP + connected UDP**. `/proc/net/udp` only has a remote endpoint for `connect()`ed sockets, so most QUIC/HTTP-3 is invisible or listed as `UDP (unresolved)` and **never drawn as an arc**. Reverse-DNS is off. Nothing leaves the machine except the traffic that was already leaving.

## Install

```sh
omarchy plugin add <git-url> --enable
```

Then, on the Omarchy box:

```sh
cd ~/.config/omarchy/plugins/io.github.chris.snitch
./build.sh
sudo ./scripts/install-privileged.sh   # optional; one polkit prompt, then blocks are silent
```

`omarchy plugin add` copies files only — it never builds binaries or installs polkit policy. Monitoring works with zero privilege once `snitchd` is built. Blocking needs the helper + policy.

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
| `/` | Search apps, IPs, countries |
| Esc | Close search, confirm dialog, or panel |

The same panel opens via `omarchy-shell shell summon io.github.chris.snitch`.

## Blocking

**Blocking uses nftables via polkit.** Monitoring does not.

`block-app` creates `/sys/fs/cgroup/snitch.slice/snitch-<app>/`, migrates the app's process tree into it, installs

```
socket cgroupv2 level 2 "snitch.slice/snitch-<app>" drop
```

on `table inet snitch`, and flushes conntrack for that app's current remotes so established flows die immediately.

If cgroup migration or the match fails, the UI offers **endpoints only — affects all apps** and will not silently substitute `block-ips`.

If no polkit authentication agent is present, block controls are greyed: `no polkit agent — monitoring only`.

`snitch-block teardown` deletes `table inet snitch` and the plugin's cgroups. Other firewall tables are never touched.

## Honest limitations

- Sub-second flows can slip between 500ms samples. The seen-set is advisory.
- TIME_WAIT and LISTEN sockets are parsed then dropped; they are not conversations.
- Other-uid processes appear as **system** (no desktop identity without privilege).
- UDP remotes via conntrack are a documented v1.1 path, not a 1.0 claim.
- Linux prebuilt binaries are not in this tree (the authoring host is macOS). Run `./build.sh` on Omarchy.
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
pkexec /usr/lib/snitch/snitch-block teardown   # if you installed the helper
sudo rm -f /usr/lib/snitch/snitch-block /usr/share/polkit-1/actions/io.github.chris.snitch.policy
```
