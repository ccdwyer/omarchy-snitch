import QtQuick
import Quickshell
import Quickshell.Io
import "ConnectionModel.js" as ConnectionModel
import "Geo.js" as Geo

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
  property bool blockingReady: polkitAgentPresent && helperInstalled && daemonAvailable
  readonly property string canonicalHelper: "/usr/lib/snitch/snitch-block"
  property string blockHint: !polkitAgentPresent
    ? "no polkit agent — monitoring only"
    : (!helperInstalled ? "block helper not installed — run ./scripts/install-privileged.sh" : "")
  property string pluginDir: adapter.pluginDir(manifest)
  property string worldDataPath: pluginDir ? pluginDir + "/data/world-paths.json" : ""
  property string replayPath: pluginDir ? pluginDir + "/data/replay.ndjson" : ""
  property var origin: ({ lat: 48.0, lon: 10.0 })
  property string lastBlockError: ""
  property string pendingIpsApp: ""
  property int restarts: 0
  property string snitchdPath: ""
  property string helperPath: ""

  SnitchAdapter { id: adapter }

  function ingest(line) {
    ConnectionModel.applyLine(model, line, Date.now())
    syncFromModel()
  }

  function syncFromModel() {
    modelRevision = model.revision
    activeCount = model.count
    pulse = model.pulse === true
    digestText = model.digestText || ""
    anyBlocked = ConnectionModel.anyBlocked(model)
  }

  function markLooked() {
    ConnectionModel.markLooked(model)
    if (eventSock.connected)
      writeSock(JSON.stringify({ type: "panel-open" }))
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
    if (ev.ok) {
      lastBlockError = (ev.verified === false && ev.warning) ? String(ev.warning) : ""
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
      lastBlockError = ev.error || "block failed"
      var failedVerb = blockProc.command && blockProc.command.length >= 3 ? blockProc.command[2] : ""
      if (failedVerb === "block-app" && blockProc.command.length >= 4)
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
    if (daemonAvailable)
      startDaemon()
    else
      startFallback()
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

  Component.onCompleted: {
    guessOrigin()
    probeBinaries()
    probePolkit()
    installCheck.running = true
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
    id: installCheck
    command: ["bash", "-c", "test -x /usr/lib/snitch/snitch-block"]
    onExited: function(code) {
      root.helperInstalled = (code === 0)
      if (code === 0)
        root.helperPath = root.canonicalHelper
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

  IpcHandler {
    target: "io.github.chris.snitch"

    function status(): string {
      return JSON.stringify({
        count: root.activeCount,
        daemon: root.daemonStatus,
        blocking: root.blockingReady,
        coverage: root.coverage,
        fallback: root.usingFallback
      })
    }

    function ping(): string { return "ok" }
  }
}
