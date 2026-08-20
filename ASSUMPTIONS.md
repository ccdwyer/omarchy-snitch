# Assumptions

Conservative choices where the Omarchy/Quickshell contract was not 100% certain.

## Service lookup from the bar widget

`shell.qml` exposes `serviceFor(pluginId)` (and `firstPartyServiceFor` as an alias). Media uses `bar.shell.firstPartyServiceFor("omarchy.media")`. Snitch uses `bar.shell.serviceFor("io.github.chris.snitch")` via `SnitchAdapter.findService`, and polls until the service instance exists because `_services` is populated asynchronously after widget construction.

The summoned `panel` instance also receives `service` from the shell loader (`if ("service" in item) item.service = shell.serviceFor(...)`). `Panel.qml` treats `snitch || service` as the same singleton.

If that injection shape changes, the adapter is the only call site for the bar; the panel uses the documented `service` property.

## Plugin source directory

Third-party manifests are stamped with `__sourceDir` in `PluginRegistry`. `snitchd`, GeoJSON, flags, and the MMDB are resolved from that path. If `__sourceDir` is absent, the daemon is treated as missing and the QML replay fallback runs.

## Unix socket client

`Quickshell.Io.Socket` is a client (`path` + `connected`) extending `DataStream`, so it takes a `SplitParser`. The daemon is a `UnixListener` at `$XDG_RUNTIME_DIR/snitch.sock`. This matches the documented Socket API; we do not use `SocketServer` from QML. Inbound commands are accumulated in a per-client buffer and split on `\n` so a split `panel-open` frame is not parsed or dropped.

## Process supervision

`Process.running = true` starts, `false` sends SIGTERM, `onExited` restarts with backoff. This is the documented Quickshell.Io.Process contract (same pattern as nightlight / network probes).

## Polkit agent detection

Preferred: `pluginRegistry.isEnabled("omarchy.polkit")` — Omarchy ships a first-party polkit agent service. Fallback: `pgrep` for common agent process names. We do **not** call `pkexec` as a probe (that can prompt or hang).

## Privileged helper install and execution

`omarchy plugin add` never runs install hooks (documented). `./scripts/install-privileged.sh` copies files with `pkexec /usr/bin/install` (not `pkexec bash`), then runs `pkexec /usr/lib/snitch/snitch-block status` so `auth_admin_keep` caches the **path-scoped helper action**. Setup may prompt twice; later blocks should not.

The polkit action annotates **only** `/usr/lib/snitch/snitch-block`. Production `pkexec` invocations always use that path. Checkout/target binaries may exist for `snitchd` monitoring; they are never used for blocking. `helperInstalled` is true only when the canonical path is executable.

`snitch-block status` (run **without** `pkexec`, so the probe cannot prompt) reports whether `nft`, `conntrack`, and cgroup v2 (`/sys/fs/cgroup/cgroup.controllers`) are present. `blockingReady` in QML is `polkitAgentPresent && helperInstalled && daemonAvailable && status.blockingReady`. Missing tools grey out block controls and set `blockHint` to the helper’s `hint` (package names). Monitoring does not consult those tools.

## Desktop icons

`DesktopEntries.heuristicLookup` + `Quickshell.iconPath` are wrapped in try/catch in `SnitchAdapter.iconSource`. The panel currently shows a letter avatar if lookup fails; snitchd still ships `icon` / `desktop` fields from `.desktop` Exec/StartupWMClass matching. Hidden and NoDisplay entries are ignored.

## IPC surface (authoritative Quattro contract)

`omarchy-shell shell summon|hide|toggle|call` apply to **panel/overlay** kinds. Snitch therefore declares `kinds: ["service", "bar-widget", "panel"]` with `entryPoints.panel: "Panel.qml"` and `keepLoaded: true`.

- Bar click still Loaders `Panel.qml` nested (clock pattern) so the popup can anchor to the pill.
- `shell summon io.github.chris.snitch` loads the panel entry point; `open(payloadJson)` / `close()` / `toggle()` / `ping()` implement the loader contract (each accepts a string arg so `shell call … ping '{}'` type-checks).
- The service IpcHandler (`omarchy-shell io.github.chris.snitch ping ''` / `status ''`) is a separate keep-loaded target for daemon health, not a substitute for `shell summon`. Every IpcHandler method takes `arg: string`.

## Theme tokens

Panel uses `qs.Ui` / `qs.Commons` (`Style`, `Color`, `KeyboardPanel`, `WidgetButton`, `ToggleSwitch`, `Panel`, `PanelKeyCatcher`, `Button`, `TextField`) exactly as the clock and network plugins do. `QtQuick.Controls` is not imported, so `Button`/`TextField` are unambiguous.

## Canvas color values

Qt Canvas 2d `strokeStyle` is given CSS `rgba()` strings, not `QColor` / `Qt.rgba`, because the latter is not reliably accepted by the 2d context.

## FileView paths

`FileView.path` is a filesystem path, not a `file://` URL (see `shell.qml`). JSON assets are loaded that way. SVG flags use `file://` Image sources.

## cgroup v2 socket match level

The nft `level` is `cgroup_match_level(path)` (component count). For `/sys/fs/cgroup/snitch.slice/snitch-<app>` that is 2. If a distro nests the slice deeper, the computed level tracks the path we actually created. Verification prefers `nft -j list table inet snitch` and requires the **same rule** to carry the path, `socket`/`cgroupv2`, the expected level, and a `drop` verdict. Text `nft list` is the fallback and matches that complete line, not a table-wide substring.

## nft CLI tokenization

`snitch-block` invokes `nft` with one argv token per word (`socket cgroupv2 level 2 <path> drop`). Brace objects (`{ type filter hook output priority 0; policy accept; }`) are a single token. `nft add` EEXIST is treated as success so verbs are idempotent.

## GeoIP MMDB API

Pinned `maxminddb` 0.25.0: `Reader::lookup<T>(IpAddr) -> Result<T, MaxMindDBError>`. Missing addresses are `Err(AddressNotFoundError)`, not `Ok(None)`. `geo.rs` matches `Ok(country)` and maps all lookup errors to `None`.

## Origin (you-are-here)

No public-IP geo (that would be outbound). Origin is a timezone centroid from `$TZ` or `/etc/localtime` / `timedatectl`, defaulting to roughly Central Europe. Overridable later via settings; not required for v1.

## Linux prebuilts

This machine is macOS (`aarch64-apple-darwin` only; no linux-musl target, no zig, no cross linker). Committing “Linux binaries” from here would be untrustworthy. **Prebuilts are delivered only via CI on git tags** (`.github/workflows/release.yml`: x86_64 + aarch64 musl, SHA-256 checksums, attached to the GitHub Release). They are never authored or checked in from this dev machine. First install on a judge box is `./build.sh`.

## Summoned panel surface

`kinds` includes `panel` so `shell summon|hide|toggle|call` match the Quattro IPC table. The **supported** open path is the bar pill (`anchorItem` from the widget). Standalone summon uses `KeyboardPanel.centerOnBar` and `shell.bar` when the host provides them; those properties are **not** in the Quattro IPC document, so summon placement is best-effort. If `shell.bar` is absent, use the pill.

## Plugin directory fallback

`manifest.__sourceDir` is stamped by PluginRegistry but is not a documented third-party API. `SnitchAdapter.pluginDir` falls back to `Qt.resolvedUrl(".")` (this QML file’s directory) so binaries, GeoJSON, flags, and replay fixtures still resolve.
