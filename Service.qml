import QtQuick
import Quickshell
import Quickshell.Io
import "ConnectionModel.js" as ConnectionModel
import "Geo.js" as Geo
import "js/Binds.js" as Binds

Item {
  id: root

  property var shell: null
  property var manifest: null
  property var pluginRegistry: null
  property string omarchyPath: ""

  readonly property string pluginId: "io.github.chris.snitch"
  readonly property string coverage: model.coverage || "TCP + connected UDP"

  property var model: ConnectionModel.emptyState()
  property int modelRevision: 0
  property int activeCount: 0
  property bool pulse: false
  property bool anyBlocked: false
  property string digestText: ""
  property string daemonStatus: "starting"
  property bool daemonAvailable: false
  property bool daemonRunning: daemonProc.running
  property bool socketConnected: eventSock.connected
  property bool usingFallback: false
  property bool polkitAgentPresent: false
  property bool helperInstalled: false
  property bool blockingToolsReady: false
  property string blockingToolsHint: ""
  property bool blockingReady: polkitAgentPresent && helperInstalled && daemonAvailable && blockingToolsReady
  readonly property string canonicalHelper: "/usr/lib/snitch/snitch-block"
  readonly property bool needsHelperInstall: !helperInstalled
  readonly property bool needsBlockingPackages: helperInstalled && !blockingToolsReady
  property bool helperInstallPending: false
  property int helperWatchTicks: 0
  property string setupWatchFor: ""
  property string blockHint: !helperInstalled
    ? "block helper not installed — click Install"
    : (!polkitAgentPresent
        ? "no polkit agent — monitoring only"
        : (!blockingToolsReady
            ? (blockingToolsHint || "install nftables and conntrack-tools (cgroup v2 required) — monitoring still works")
            : ""))
  property string pluginDir: adapter.pluginDir(manifest)
  property string worldDataPath: pluginDir ? pluginDir + "/data/world-paths.json" : ""
  property string replayPath: pluginDir ? pluginDir + "/data/replay.ndjson" : ""
  property var origin: ({ lat: 48.0, lon: 10.0 })
  property string lastBlockError: ""
  property string pendingIpsApp: ""
  property int restarts: 0
  property string snitchdPath: ""
  property string helperPath: ""
  property bool offerBinds: true
  property string offerNote: "Set Super+Alt+S to open Snitch"
  property var workQueue: []
  property var workCurrent: null

  SnitchAdapter { id: adapter }

  function ingest(line) {
    ConnectionModel.applyLine(model, line, Date.now())
    syncFromModel()
  }

  function syncFromModel() {
    modelRevision = model.revision
    activeCount = model.count
    pulse = model.pulse === true && !usingFallback
    digestText = model.digestText || ""
    anyBlocked = ConnectionModel.anyBlocked(model)
  }

  function rerun(proc) {
    if (!proc)
      return
    proc.running = false
    proc.running = true
  }

  function refreshInstallState() {
    rerun(installCheck)
    if (!helperInstalled && !daemonAvailable)
      probeBinaries()
    else if (helperInstalled)
      probeHelperStatus()
  }

  function markLooked() {
    ConnectionModel.markLooked(model)
    if (eventSock.connected)
      writeSock(JSON.stringify({ type: "panel-open" }))
    refreshInstallState()
    syncFromModel()
  }

  function clearPulse() {
    ConnectionModel.clearPulse(model)
    syncFromModel()
  }

  function appById(id) {
    return model.apps && model.apps[id] ? model.apps[id] : null
  }

  function appIcon(app) {
    if (!app)
      return ""
    return adapter.iconSource(app.desktop || app.id, app.icon)
  }

  function filteredApps(query) {
    return ConnectionModel.filterApps(model.ordered, query)
  }

  function drawableArcs() {
    return ConnectionModel.drawableArcs(model.connections, origin, 40)
  }

  function writeSock(s) {
    try {
      eventSock.write(s + "\n")
      eventSock.flush()
    } catch (e) { }
  }

  function startDaemon() {
    if (!snitchdPath) {
      daemonStatus = "missing"
      startFallback()
      return
    }
    usingFallback = false
    daemonProc.command = [
      snitchdPath,
      "--socket", adapter.socketPath(),
      "--data-dir", pluginDir + "/data",
      "--state-dir", adapter.stateDir(),
      "--interval-ms", "500"
    ]
    daemonStatus = "starting"
    daemonProc.running = true
  }

  function startFallback() {
    usingFallback = true
    daemonStatus = "fallback"
    fallbackIndex = 0
    fallbackTimer.stop()
    if (replayView.text && replayView.text().trim())
      fallbackTimer.restart()
    else
      replayView.reload()
  }

  function requestBlock(appId) {
    var app = appById(appId)
    if (!app || !blockingReady)
      return
    if (!ConnectionModel.isBlockable(app)) {
      lastBlockError = "refusing to block system/unknown identity"
      return
    }
    if (app.blocked) {
      if (app.mechanism === "endpoints")
        runHelper(["unblock-ips", appId])
      else
        runHelper(["unblock-app", appId])
      return
    }
    var args = ["block-app", appId]
    var pids = ConnectionModel.pidsOf(app)
    for (var i = 0; i < pids.length; i++)
      args.push(String(pids[i]))
    lastBlockError = ""
    runHelper(args)
  }

  function requestBlockIps(appId) {
    var app = appById(appId)
    if (!app || !blockingReady)
      return
    if (!ConnectionModel.isBlockable(app)) {
      lastBlockError = "refusing to block system/unknown identity"
      return
    }
    var ips = ConnectionModel.remotesOf(app)
    if (ips.length === 0) {
      lastBlockError = "no endpoints to block"
      return
    }
    var args = ["block-ips", appId]
    for (var i = 0; i < ips.length; i++)
      args.push(ips[i])
    pendingIpsApp = ""
    runHelper(args)
  }

  function offerIpsFallback(appId, err) {
    pendingIpsApp = appId
    lastBlockError = err || "cgroup block failed"
  }

  function runHelper(args) {
    if (!helperInstalled) {
      lastBlockError = "canonical helper missing at " + canonicalHelper
      return
    }
    var cmd = ["pkexec", canonicalHelper]
    for (var i = 0; i < args.length; i++)
      cmd.push(args[i])
    if (blockProc.running)
      return
    blockProc.command = cmd
    blockProc.running = true
  }

  function onBlockOutput(text) {
    var raw = String(text || "").trim()
    var ev
    try { ev = JSON.parse(raw) } catch (e) {
      lastBlockError = raw || "helper produced no JSON"
      return
    }
    if (ev.ok && ev.verified !== false) {
      lastBlockError = ev.warning ? String(ev.warning) : ""
      if (ev.teardown) {
        model.blocked = {}
        ConnectionModel.rebuild(model, Date.now())
        syncFromModel()
        return
      }
      var appId = ev.app || (blockProc.command && blockProc.command.length > 2 ? blockProc.command[2] : "")
      // pkexec argv: pkexec bin verb appId...
      if (!appId && blockProc.command && blockProc.command.length >= 4)
        appId = blockProc.command[3]
      var verb = blockProc.command && blockProc.command.length >= 3 ? blockProc.command[2] : ""
      if (verb === "unblock-app" || verb === "unblock-ips") {
        if (blockProc.command.length >= 4)
          ConnectionModel.setBlocked(model, blockProc.command[3], "")
      } else if (verb === "block-app" || verb === "block-ips") {
        var id = blockProc.command[3]
        ConnectionModel.setBlocked(model, id, ev.mechanism || (verb === "block-ips" ? "endpoints" : "cgroup"))
      }
      syncFromModel()
    } else {
      lastBlockError = ev.error || (ev.warning ? String(ev.warning) : "") || "block incomplete"
      var failedVerb = blockProc.command && blockProc.command.length >= 3 ? blockProc.command[2] : ""
      // Only offer host-wide IP fallback when cgroup work was fully rolled back
      // (or never started, e.g. root-cgroup). If restore failed, processes may
      // still sit in snitch.slice — stacking an IP-set on that is unsafe.
      var rolled = ev.rollback === true || ev.code === "root-cgroup" || ev.code === "empty-forest"
      if (failedVerb === "block-app" && blockProc.command.length >= 4 && rolled)
        offerIpsFallback(blockProc.command[3], ev.error)
    }
  }

  function probeBinaries() {
    findBinProc.command = [
      "bash", "-c",
      "dir=" + shellQuote(pluginDir) + "; " +
      "found=''; " +
      "for p in \"$dir/bin/snitchd\" \"$dir/target/release/snitchd\" \"$dir/target/debug/snitchd\"; do " +
      "  if [ -x \"$p\" ]; then found=$p; break; fi; " +
      "done; " +
      "if [ -z \"$found\" ]; then found=$(command -v snitchd 2>/dev/null || true); fi; " +
      "printf 'snitchd=%s\\n' \"$found\"; " +
      "if [ -x /usr/lib/snitch/snitch-block ]; then printf 'helper=/usr/lib/snitch/snitch-block\\n'; else printf 'helper=\\n'; fi"
    ]
    findBinProc.running = true
  }

  function shellQuote(s) {
    return "'" + String(s || "").replace(/'/g, "'\\''") + "'"
  }

  function privilegedInstallCommand() {
    var dir = pluginDir
    if (!dir)
      return ""
    return "cd " + shellQuote(dir) + " && ./scripts/setup-from-ui.sh"
  }

  function launchSetupTerminal(inner) {
    if (!inner)
      return false
    try {
      Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", inner])
      return true
    } catch (e) {
      lastBlockError = "could not open a terminal"
      return false
    }
  }

  function watchHelperInstall(kind) {
    setupWatchFor = kind || "helper"
    helperInstallPending = true
    helperWatchTicks = 0
    helperWatch.restart()
  }

  function installPrivilegedHelper() {
    if (helperInstalled || helperInstallPending)
      return
    if (!launchSetupTerminal(privilegedInstallCommand()))
      return
    watchHelperInstall("helper")
  }

  function installBlockingPackages() {
    if (helperInstallPending)
      return
    if (!launchSetupTerminal("omarchy pkg add nftables conntrack-tools"))
      return
    watchHelperInstall("packages")
  }

  function applyBindPlan(plan) {
    var p = plan || Binds.offer
    root.offerBinds = !!p.needed
    root.offerNote = String(p.note || "")
    Binds.setOffer(p)
  }

  function enqueueWork(command, done) {
    workQueue.push({ command: command, done: done || null })
    runWork()
  }

  function runWork() {
    if (bindWorkProc.running || root.workCurrent)
      return
    if (!workQueue.length)
      return
    root.workCurrent = workQueue.shift()
    bindWorkProc.command = root.workCurrent.command
    bindWorkProc.running = true
  }

  function scanBinds() {
    enqueueWork(["hyprctl", "-j", "binds"], function(text, code) {
      if (Number(code) !== 0) {
        root.offerBinds = true
        if (!root.offerNote)
          root.offerNote = "Set Super+Alt+S to open Snitch"
        return
      }
      root.applyBindPlan(Binds.applyScan(text))
    })
  }

  function notifyNewBinds(plan) {
    var body = Binds.notifyBody(plan.toAdd, plan.skipped)
    if (!body)
      return
    Quickshell.execDetached(Binds.notifyArgv("Snitch", "Snitch keybinding", body))
  }

  // Only called from an explicit Set hotkey click (or installBinds IPC).
  // Never from Component.onCompleted / scanBinds.
  function installBinds(arg) {
    var _a = arg
    enqueueWork(["hyprctl", "-j", "binds"], function(text, code) {
      if (Number(code) !== 0) {
        root.offerNote = "could not read keybinds"
        root.offerBinds = true
        return
      }
      var plan = Binds.applyScan(text)
      if (!plan.toAdd || !plan.toAdd.length) {
        root.applyBindPlan(plan)
        return
      }
      var lua = Binds.luaBlock(plan.toAdd)
      enqueueWork(["python3", root.pluginDir + "/compat/install-binds.py", root.pluginId, lua], function(out, instCode) {
        if (Number(instCode) !== 0) {
          root.offerNote = "could not write ~/.config/hypr/bindings.lua"
          root.offerBinds = true
          return
        }
        root.notifyNewBinds(plan)
        Qt.callLater(root.scanBinds)
      })
    })
    return "ok"
  }

  function buildSnitchd() {
    if (helperInstallPending)
      return
    var dir = pluginDir
    if (!dir)
      return
    if (!launchSetupTerminal("cd " + shellQuote(dir) + " && ./build.sh"))
      return
    watchHelperInstall("daemon")
  }

  function applyBinaryMap(text) {
    var lines = String(text || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      var pair = lines[i].split("=")
      if (pair.length < 2)
        continue
      var k = pair[0]
      var v = pair.slice(1).join("=").trim()
      if (k === "snitchd")
        snitchdPath = v
      if (k === "helper")
        helperPath = v
    }
    daemonAvailable = snitchdPath !== ""
    helperInstalled = helperPath === canonicalHelper
    if (!helperInstalled)
      blockingToolsReady = false
    else
      probeHelperStatus()
    if (daemonAvailable)
      startDaemon()
    else
      startFallback()
  }

  function probeHelperStatus() {
    if (!helperInstalled)
      return
    if (helperStatusProc.running)
      return
    helperStatusProc.command = [canonicalHelper, "status"]
    helperStatusProc.running = true
  }

  function applyHelperStatus(text) {
    var raw = String(text || "").trim()
    var ev
    try { ev = JSON.parse(raw) } catch (e) {
      blockingToolsReady = false
      blockingToolsHint = "helper status unreadable — install nftables and conntrack-tools (cgroup v2 required). Monitoring still works."
      return
    }
    blockingToolsReady = ev.blockingReady === true
    blockingToolsHint = ev.hint ? String(ev.hint) : ""
    if (!blockingToolsReady && !blockingToolsHint) {
      var pkgs = ev.packages
      if (pkgs && pkgs.length)
        blockingToolsHint = "install " + pkgs.join(", ") + " — blocking requires nftables, conntrack-tools, and cgroup v2"
      else
        blockingToolsHint = "blocking unavailable — need nftables, conntrack-tools, and cgroup v2. Monitoring still works."
    }
  }

  function probePolkit() {
    if (adapter.polkitEnabled(pluginRegistry)) {
      polkitAgentPresent = true
      return
    }
    polkitProc.command = [
      "bash", "-c",
      "pgrep -af 'PolkitAgent|polkit-gnome-authentication-agent|polkit-kde-authentication-agent|lxqt-policykit|mate-polkit|xfce-polkit' >/dev/null"
    ]
    polkitProc.running = true
  }

  function guessOrigin() {
    var tz = ""
    try { tz = Quickshell.env("TZ") || "" } catch (e) { tz = "" }
    origin = Geo.timezoneOrigin(tz)
    if (!tz)
      tzProc.running = true
  }

  onPluginRegistryChanged: probePolkit()

  Component.onCompleted: {
    guessOrigin()
    probeBinaries()
    probePolkit()
    installCheck.running = true
    Qt.callLater(root.scanBinds)
  }

  Process {
    id: findBinProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyBinaryMap(text)
    }
  }

  Process {
    id: polkitProc
    onExited: function(code) { root.polkitAgentPresent = (code === 0) || adapter.polkitEnabled(root.pluginRegistry) }
  }

  Process {
    id: tzProc
    command: ["bash", "-c", "readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||'; timedatectl show -p Timezone --value 2>/dev/null | head -1"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var tz = String(text || "").trim().split("\n")[0]
        if (tz)
          root.origin = Geo.timezoneOrigin(tz)
      }
    }
  }

  Process {
    id: helperStatusProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyHelperStatus(text)
    }
    onExited: function(code) {
      if (code !== 0 && !root.blockingToolsReady)
        root.blockingToolsHint = root.blockingToolsHint || "helper status failed — install nftables and conntrack-tools (cgroup v2 required)"
    }
  }

  Process {
    id: installCheck
    command: ["bash", "-c", "test -x /usr/lib/snitch/snitch-block"]
    onExited: function(code) {
      root.helperInstalled = (code === 0)
      if (code === 0) {
        root.helperPath = root.canonicalHelper
        root.probeHelperStatus()
      } else {
        root.blockingToolsReady = false
      }
    }
  }

  Process {
    id: daemonProc
    stdout: StdioCollector { }
    stderr: StdioCollector { }
    onStarted: {
      root.daemonStatus = "starting"
      sockConnectDelay.restart()
    }
    onExited: function() {
      eventSock.connected = false
      root.restarts += 1
      root.daemonStatus = "reconnecting"
      restartTimer.interval = Math.min(8000, 400 * Math.pow(2, Math.min(root.restarts, 5)))
      restartTimer.restart()
    }
  }

  Timer {
    id: restartTimer
    interval: 800
    repeat: false
    onTriggered: {
      if (root.snitchdPath)
        root.startDaemon()
    }
  }

  Timer {
    id: sockConnectDelay
    interval: 120
    repeat: false
    onTriggered: {
      eventSock.path = adapter.socketPath()
      eventSock.connected = true
    }
  }

  Socket {
    id: eventSock
    path: adapter.socketPath()
    connected: false
    parser: SplitParser {
      onRead: function(line) { root.ingest(line) }
    }
    onConnectedChanged: {
      if (connected) {
        root.daemonStatus = "connected"
        root.usingFallback = false
        root.restarts = 0
      } else if (root.daemonAvailable && !daemonProc.running) {
        root.daemonStatus = "reconnecting"
      }
    }
    onError: function() {
      if (root.daemonStatus === "starting" || root.daemonStatus === "reconnecting")
        sockRetry.restart()
    }
  }

  Timer {
    id: sockRetry
    interval: 250
    repeat: false
    onTriggered: {
      if (!eventSock.connected && root.daemonAvailable)
        eventSock.connected = true
    }
  }

  Process {
    id: blockProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onBlockOutput(text)
    }
    stderr: StdioCollector {
      id: blockErr
      waitForEnd: true
    }
    onExited: function(code) {
      if (code !== 0 && !root.lastBlockError)
        root.lastBlockError = (blockErr.text || "helper exit " + code).trim()
    }
  }

  FileView {
    id: replayView
    path: root.replayPath
    watchChanges: false
    printErrors: false
    onLoaded: {
      if (root.usingFallback && !fallbackTimer.running) {
        root.fallbackIndex = 0
        fallbackTimer.restart()
      }
    }
  }

  property int fallbackIndex: 0

  Timer {
    id: fallbackTimer
    interval: 90
    repeat: true
    onTriggered: {
      var raw = replayView.text ? replayView.text() : ""
      var lines = String(raw || "").split("\n")
      if (fallbackIndex >= lines.length) {
        fallbackTimer.stop()
        return
      }
      root.ingest(lines[fallbackIndex])
      fallbackIndex += 1
    }
  }

  Timer {
    id: pulseClear
    interval: 2200
    running: root.pulse
    repeat: false
    onTriggered: root.clearPulse()
  }

  Process {
    id: bindWorkProc
    running: false
    stdout: StdioCollector {
      id: bindWorkOut
      waitForEnd: true
    }
    onExited: function(exitCode) {
      var text = bindWorkOut.text
      var job = root.workCurrent
      root.workCurrent = null
      if (job && job.done) {
        try {
          job.done(text, exitCode)
        } catch (e) {
          console.warn("snitch: bind work callback failed", e)
        }
      }
      root.runWork()
    }
  }

  Timer {
    interval: 4000
    repeat: true
    running: true
    onTriggered: root.scanBinds()
  }

  IpcHandler {
    target: "io.github.chris.snitch"

    function status(arg: string): string {
      return JSON.stringify({
        count: root.activeCount,
        daemon: root.daemonStatus,
        blocking: root.blockingReady,
        coverage: root.coverage,
        fallback: root.usingFallback,
        helper: root.helperInstalled,
        polkit: root.polkitAgentPresent,
        needsHelper: root.needsHelperInstall,
        bindOfferNeeded: root.offerBinds,
        bindOfferNote: root.offerNote
      })
    }

    function ping(arg: string): string { return "ok" }

    function installBinds(arg: string): string { return root.installBinds(arg) }

    function install(arg: string): string {
      root.installPrivilegedHelper()
      return "launched"
    }

    function refresh(arg: string): string {
      root.refreshInstallState()
      return JSON.stringify({ helper: root.helperInstalled, blocking: root.blockingReady })
    }
  }

  Timer {
    interval: 2500
    running: !root.helperInstalled
    repeat: true
    onTriggered: root.refreshInstallState()
  }

  Timer {
    id: helperWatch
    interval: 2000
    repeat: true
    onTriggered: {
      root.helperWatchTicks += 1
      if (root.helperWatchTicks > 300) {
        stop()
        root.helperInstallPending = false
        root.setupWatchFor = ""
        return
      }
      root.refreshInstallState()
      var done = false
      if (root.setupWatchFor === "packages")
        done = root.blockingToolsReady
      else if (root.setupWatchFor === "daemon")
        done = root.daemonAvailable
      else
        done = root.helperInstalled
      if (done) {
        stop()
        root.helperInstallPending = false
        root.setupWatchFor = ""
      }
    }
  }
}
