import QtQuick
import qs.Ui
import qs.Commons

BarWidget {
  id: root
  moduleName: "io.github.chris.snitch"

  property var shell: null

  SnitchAdapter { id: adapter }

  property var snitch: null

  readonly property int count: snitch ? snitch.activeCount : 0
  readonly property bool blocked: snitch ? snitch.anyBlocked === true : false
  readonly property string daemonStatus: snitch ? String(snitch.daemonStatus) : "starting"
  readonly property bool connected: daemonStatus === "connected" || daemonStatus === "fallback"
  readonly property bool needsHelperInstall: snitch ? snitch.needsHelperInstall === true : false
  readonly property bool pulse: {
    if (!snitch || needsHelperInstall)
      return false
    if (snitch.usingFallback === true)
      return false
    return snitch.pulse === true
  }

  readonly property string pillText: {
    if (!snitch)
      return "…"
    if (daemonStatus === "missing")
      return "—"
    if (daemonStatus === "reconnecting" || daemonStatus === "starting")
      return "…"
    return String(count)
  }

  readonly property string tooltip: {
    if (!snitch)
      return "Snitch — waiting for service"
    if (needsHelperInstall)
      return "Snitch — click to open, then Install helper"
    if (daemonStatus === "missing")
      return "Snitch — snitchd not built (click to build)"
    if (daemonStatus === "reconnecting")
      return "Snitch — reconnecting"
    if (daemonStatus === "fallback")
      return "Snitch — replay fallback (" + count + ")"
    if (blocked)
      return "Snitch — " + count + " connections, block active"
    if (pulse)
      return "Snitch — new network " + (snitch.model && snitch.model.pulseNetwork ? snitch.model.pulseNetwork : "")
    return "Snitch — " + count + " live connections (TCP + connected UDP)"
  }

  function refreshService() {
    snitch = adapter.findService(root.bar, root.shell, null)
  }

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function open() {
    if (panelLoader.item)
      panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item)
      panelLoader.item.close()
  }

  function toggle() {
    if (panelLoader.item)
      panelLoader.item.toggle()
  }

  function closeForPopoutSwitch() {
    if (panelLoader.item)
      panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    var target = panelLoader.item
    if (!target)
      return
    if ("bar" in target)
      target.bar = root.bar
    if ("anchorItem" in target)
      target.anchorItem = button
    if ("hostWidget" in target)
      target.hostWidget = root
    if ("snitch" in target)
      target.snitch = root.snitch
    if ("pluginDir" in target)
      target.pluginDir = root.snitch && root.snitch.pluginDir ? root.snitch.pluginDir : ""
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onBarChanged: {
    refreshService()
    injectPanel()
  }
  onSnitchChanged: injectPanel()

  Component.onCompleted: refreshService()

  Timer {
    interval: 400
    running: root.snitch === null
    repeat: true
    onTriggered: root.refreshService()
  }

  Connections {
    target: root.snitch
    function onPulseChanged() { pulseAnim.restart() }
    function onModelRevisionChanged() { }
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.pillText
    tooltipText: root.tooltip
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.LeftButton || buttonCode === Qt.RightButton)
        root.toggle()
    }

    Rectangle {
      id: pulseHalo
      anchors.fill: parent
      anchors.margins: -2
      radius: height / 2
      color: "transparent"
      border.width: 2
      border.color: root.blocked
        ? (root.bar && root.bar.urgent ? root.bar.urgent : "#e25c5c")
        : (root.pulse ? "#e2a84b" : "transparent")
      opacity: root.blocked ? 0.9 : pulseHalo.pulseOpacity
      property real pulseOpacity: root.pulse ? 1 : 0
      Behavior on border.color { ColorAnimation { duration: 180 } }
    }

    SequentialAnimation {
      id: pulseAnim
      loops: 4
      NumberAnimation { target: pulseHalo; property: "pulseOpacity"; from: 1; to: 0.15; duration: 280 }
      NumberAnimation { target: pulseHalo; property: "pulseOpacity"; from: 0.15; to: 1; duration: 280 }
      onStopped: pulseHalo.pulseOpacity = root.pulse ? 1 : (root.blocked ? 0.9 : 0)
    }
  }
}
