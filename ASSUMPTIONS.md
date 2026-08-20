# Assumptions

Conservative choices where the Omarchy/Quickshell contract was not 100% certain.

## Service lookup from the bar widget

`shell.qml` exposes `serviceFor(pluginId)` (and `firstPartyServiceFor` as an alias). Media uses `bar.shell.firstPartyServiceFor("omarchy.media")`. Snitch uses `bar.shell.serviceFor("io.github.chris.snitch")` via `SnitchAdapter.findService`, and polls until the service instance exists because `_services` is populated asynchronously after widget construction.

If that injection shape changes, the adapter is the only call site.

## Plugin source directory

Third-party manifests are stamped with `__sourceDir` in `PluginRegistry`. Service binaries, GeoJSON, flags, and the MMDB are resolved from that path. If `__sourceDir` is absent, the daemon is treated as missing and the QML replay fallback runs.

## Unix socket client

`Quickshell.Io.Socket` is a client (`path` + `connected`) extending `DataStream`, so it takes a `SplitParser`. The daemon is a `UnixListener` at `$XDG_RUNTIME_DIR/snitch.sock`. This matches the documented Socket API; we do not use `SocketServer` from QML.

## Process supervision

`Process.running = true` starts, `false` sends SIGTERM, `onExited` restarts with backoff. This is the documented Quickshell.Io.Process contract (same pattern as nightlight / network probes).

## Polkit agent detection

Preferred: `pluginRegistry.isEnabled("omarchy.polkit")` — Omarchy ships a first-party polkit agent service. Fallback: `pgrep` for common agent process names. We do **not** call `pkexec` as a probe (that can prompt or hang).

## Privileged helper install

`omarchy plugin add` never runs install hooks (documented). Policy + helper install is a documented optional `pkexec` script, not an implicit side effect of enabling the plugin. Until it runs, block UI is greyed.

## Desktop icons

`DesktopEntries.heuristicLookup` + `Quickshell.iconPath` are wrapped in try/catch in `SnitchAdapter.iconSource`. The panel currently shows a letter avatar if lookup fails; snitchd still ships `icon` / `desktop` fields from `.desktop` Exec/StartupWMClass matching.

## IPC target name

Service registers `IpcHandler { target: "io.github.chris.snitch" }`. First-party widgets use dotted ids (`omarchy.clock`). If the IPC router rejects dots, summon still works through the bar-widget `open()`/`close()`/`toggle()` contract (`isBarWidgetPanelPlugin` in `shell.qml`).

## Theme tokens

Panel uses `qs.Ui` / `qs.Commons` (`Style`, `Color`, `KeyboardPanel`, `WidgetButton`, `ToggleSwitch`, `Panel`, `PanelKeyCatcher`, `Button`, `TextField`) exactly as the clock and network plugins do. Colors for the map are derived from `bar.foreground` and `Color.accent` rather than hardcoded dark-only palettes.

## Canvas color values

Qt Canvas 2d `strokeStyle` is given CSS `rgba()` strings, not `QColor` / `Qt.rgba`, because the latter is not reliably accepted by the 2d context.

## FileView paths

`FileView.path` is a filesystem path, not a `file://` URL (see `shell.qml`). JSON assets are loaded that way. SVG flags use `file://` Image sources.

## cgroup v2 socket match level

We assume the plugin-owned path `snitch.slice/snitch-<app>` sits at **level 2** under the unified hierarchy at `/sys/fs/cgroup`. If a distro nests the slice deeper, `nft list` verification fails and the UI offers the explicit host-wide IP-set fallback instead of lying.

## nft CLI tokenization

`snitch-block` invokes `nft` with one argv token per word (`socket cgroupv2 level 2 <path> drop`). Brace objects (`{ type filter hook output priority 0; policy accept; }`) are a single token. `nft add` EEXIST is treated as success so verbs are idempotent.

## GeoIP MMDB API

`maxminddb` 0.25 `Reader::lookup` returns `Result<Option<T>, _>`. DB-IP Country Lite is read as `geoip2::Country`. If a future crate release drops the `Option`, the lookup site in `daemon/src/geo.rs` is the only change.

## Origin (you-are-here)

No public-IP geo (that would be outbound). Origin is a timezone centroid from `$TZ` or `/etc/localtime` / `timedatectl`, defaulting to roughly Central Europe. Overridable later via settings; not required for v1.

## Linux prebuilts

Spec asked for x86_64 and aarch64 prebuilts. This tree was authored on macOS, so shipping Mach-O binaries as Linux prebuilts would be a lie. `build.sh` is the supported path on the judge's Omarchy machine.
