import QtQuick
import qs.Commons
import qs.Ui
import "ConnectionModel.js" as ConnectionModel

Panel {
  id: root
  moduleName: "io.github.chris.snitch"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  property var snitch: null
  property var service: null
  property var shell: null
  property var manifest: null
  property string pluginDir: ""

  property string searchQuery: ""
  property int selectedIndex: 0
  property bool searchOpen: false
  property bool confirmIps: false

  readonly property var barIdentity: hostWidget || root
  readonly property var liveBar: bar || (shell && shell.bar ? shell.bar : null)
  readonly property var liveSnitch: snitch || service || (hostWidget && hostWidget.snitch ? hostWidget.snitch : null)
  readonly property color fg: liveBar ? liveBar.foreground : Color.foreground
  readonly property color accent: Color.accent
  readonly property string fontFamily: liveBar ? liveBar.fontFamily : Style.font.family
  readonly property int modelRev: liveSnitch ? liveSnitch.modelRevision : 0
  readonly property var apps: {
    var _r = modelRev
    if (!liveSnitch)
      return []
    return ConnectionModel.filterApps(liveSnitch.model.ordered, searchQuery)
  }
  readonly property var arcs: {
    var _r = modelRev
    return liveSnitch && liveSnitch.drawableArcs ? liveSnitch.drawableArcs() : []
  }
  readonly property string digest: liveSnitch ? (liveSnitch.digestText || "") : ""
  readonly property string coverage: liveSnitch ? liveSnitch.coverage : "TCP + connected UDP"
  readonly property bool blockingReady: liveSnitch ? liveSnitch.blockingReady === true : false
  readonly property string blockHint: liveSnitch ? (liveSnitch.blockHint || "") : ""
  readonly property string hoverLabel: map.hoverArc ? hoverText(map.hoverArc) : ""
  readonly property string pendingIpsApp: liveSnitch ? (liveSnitch.pendingIpsApp || "") : ""
  readonly property string lastBlockError: liveSnitch ? (liveSnitch.lastBlockError || "") : ""
  readonly property string daemonLine: !liveSnitch ? "waiting for service"
    : (liveSnitch.daemonStatus === "fallback" ? "replay fallback — build snitchd for live capture"
    : (liveSnitch.daemonStatus === "missing" ? "snitchd not built — run ./build.sh"
    : (liveSnitch.daemonStatus === "reconnecting" ? "reconnecting to snitchd…"
    : (liveSnitch.daemonStatus === "connected" ? coverage : liveSnitch.daemonStatus))))

  onServiceChanged: {
    if (service && !snitch)
      snitch = service
    if (service && service.pluginDir)
      pluginDir = service.pluginDir
  }

  function open(payloadJson) {
    var _p = payloadJson
    if (service && !snitch)
      snitch = service
    if (liveSnitch && liveSnitch.markLooked)
      liveSnitch.markLooked()
    selectedIndex = 0
    searchQuery = ""
    searchOpen = false
    confirmIps = false
    root.controller.show()
  }

  function close(arg) {
    confirmIps = false
    searchOpen = false
    root.controller.hide()
  }

  function toggle(arg) {
    if (root.opened)
      root.close()
    else
      root.open(arg && String(arg).length ? arg : "{}")
  }

  function ping(arg) {
    return "ok"
  }

  function switchPanel(direction) {
    if (root.liveBar && typeof root.liveBar.switchPanelFrom === "function")
      return root.liveBar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  function hoverText(c) {
    if (!c)
      return ""
    var app = c.app && c.app.name ? c.app.name : "?"
    var ip = c.remote && c.remote.ip ? c.remote.ip : ""
    var port = c.remote && c.remote.port ? c.remote.port : ""
    var flag = c.country ? c.country : ""
    return app + " → " + ip + (port ? ":" + port : "") + (flag ? ", " + flag : "")
  }

  function selectedApp() {
    if (selectedIndex < 0 || selectedIndex >= apps.length)
      return null
    return apps[selectedIndex]
  }

  function moveSelection(dy) {
    if (apps.length === 0) {
      selectedIndex = 0
      return
    }
    selectedIndex = Math.max(0, Math.min(apps.length - 1, selectedIndex + dy))
    appList.positionViewAtIndex(selectedIndex, ListView.Contain)
  }

  function canBlockApp(a) {
    return ConnectionModel.isBlockable(a) && blockingReady
  }

  function toggleSelectedBlock() {
    var a = selectedApp()
    if (!canBlockApp(a) || !liveSnitch)
      return
    liveSnitch.requestBlock(a.id)
  }

  function confirmIpsBlock() {
    if (!liveSnitch || !pendingIpsApp)
      return
    if (!ConnectionModel.isBlockable(liveSnitch.appById ? liveSnitch.appById(pendingIpsApp) : { id: pendingIpsApp }))
      return
    liveSnitch.requestBlockIps(pendingIpsApp)
    confirmIps = false
  }

  onPendingIpsAppChanged: {
    if (pendingIpsApp)
      confirmIps = true
  }

  onAppsChanged: {
    if (selectedIndex >= apps.length)
      selectedIndex = Math.max(0, apps.length - 1)
  }

  // Bar click supplies anchorItem. Summon does not — centerOnBar + shell.bar
  // is best-effort (not in the Quattro IPC table). Pill is the supported path.
  Item {
    id: summonAnchor
    width: 1
    height: 1
    visible: false
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem ? root.anchorItem : summonAnchor
    owner: root.barIdentity
    bar: root.liveBar
    centerOnBar: !root.anchorItem
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(560))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      blocked: root.searchOpen || root.confirmIps

      onMoveRequested: function(dx, dy) {
        if (dy !== 0)
          root.moveSelection(dy)
      }
      onActivateRequested: root.toggleSelectedBlock()
      onCloseRequested: {
        if (root.confirmIps)
          root.confirmIps = false
        else if (root.searchOpen) {
          root.searchOpen = false
          root.searchQuery = ""
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "b" || t === "B")
          root.toggleSelectedBlock()
        else if (t === "/") {
          root.searchOpen = true
          Qt.callLater(function() { if (searchField) searchField.forceActiveFocus() })
        } else if (t === "r" || t === "R") {
          if (root.liveSnitch && root.liveSnitch.markLooked)
            root.liveSnitch.markLooked()
        }
      }

      Column {
        id: column
        width: parent.width
        spacing: Style.space(10)

        Item {
          width: parent.width
          height: heroCol.height
          Column {
            id: heroCol
            width: parent.width
            spacing: Style.space(4)
            Text {
              text: "SNITCH"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.4
            }
            Text {
              width: parent.width
              text: root.digest !== "" ? root.digest : root.daemonLine
              color: root.digest !== "" ? root.accent : Qt.darker(root.fg, 1.4)
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }
        }

        WorldMap {
          id: map
          width: parent.width
          height: Style.space(220)
          pluginDir: root.pluginDir || (root.liveSnitch ? root.liveSnitch.pluginDir : "")
          worldDataPath: root.liveSnitch ? root.liveSnitch.worldDataPath : ""
          arcs: root.arcs
          origin: root.liveSnitch && root.liveSnitch.origin ? root.liveSnitch.origin : ({ lat: 48, lon: 10 })
          landColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.16)
          borderColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.28)
          oceanColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.04)
          accentColor: root.accent
          extraHidden: {
            var _r = root.modelRev
            if (!root.liveSnitch || !root.liveSnitch.model)
              return 0
            var n = 0
            var cons = root.liveSnitch.model.connections || {}
            for (var k in cons) {
              if (cons[k] && !cons[k].unresolved && cons[k].country)
                n++
            }
            return Math.max(0, n - root.arcs.length)
          }
        }

        Text {
          width: parent.width
          visible: root.hoverLabel !== ""
          text: root.hoverLabel
          color: root.fg
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }

        Text {
          width: parent.width
          text: "Coverage: " + root.coverage + ". Unresolved UDP is listed, never drawn. Reverse-DNS is off."
          color: Qt.darker(root.fg, 1.6)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Row {
          width: parent.width
          spacing: Style.space(8)
          visible: root.searchOpen
          Text {
            text: "/"
            color: root.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            anchors.verticalCenter: parent.verticalCenter
          }
          TextField {
            id: searchField
            width: parent.width - Style.space(24)
            foreground: root.fg
            font.family: root.fontFamily
            placeholderText: "search apps, IPs, countries"
            text: root.searchQuery
            onTextChanged: root.searchQuery = text
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Escape) {
                root.searchOpen = false
                root.searchQuery = ""
                keyCatcher.forceActiveFocus()
                event.accepted = true
              } else if (event.key === Qt.Key_Down) {
                root.moveSelection(1)
                event.accepted = true
              } else if (event.key === Qt.Key_Up) {
                root.moveSelection(-1)
                event.accepted = true
              } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                root.toggleSelectedBlock()
                event.accepted = true
              }
            }
          }
        }

        PanelSeparator { foreground: root.fg }

        Text {
          visible: root.apps.length === 0
          width: parent.width
          text: root.liveSnitch && root.liveSnitch.daemonStatus === "connected"
            ? "No outbound conversations right now."
            : "Waiting for connections."
          color: Qt.darker(root.fg, 1.5)
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
        }

        ListView {
          id: appList
          width: parent.width
          height: Math.min(contentHeight, Style.space(240))
          clip: true
          spacing: Style.space(4)
          boundsBehavior: Flickable.StopAtBounds
          model: root.apps
          currentIndex: root.selectedIndex
          delegate: Rectangle {
            id: row
            required property var modelData
            required property int index
            width: ListView.view.width
            height: rowInner.implicitHeight + Style.space(10)
            radius: Style.cornerRadius
            color: index === root.selectedIndex
              ? Style.selectedFillFor(root.fg, root.accent)
              : (rowMouse.containsMouse ? Style.hoverFillFor(root.fg, root.accent) : "transparent")

            MouseArea {
              id: rowMouse
              anchors.fill: parent
              hoverEnabled: true
              onClicked: root.selectedIndex = index
            }

            Row {
              id: rowInner
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(8)
              anchors.rightMargin: Style.space(8)
              spacing: Style.space(8)

              Image {
                width: Style.space(20)
                height: Style.space(20)
                fillMode: Image.PreserveAspectFit
                asynchronous: true
                source: root.liveSnitch && root.liveSnitch.appIcon ? root.liveSnitch.appIcon(modelData) : ""
                visible: status === Image.Ready
                anchors.verticalCenter: parent.verticalCenter
              }

              Text {
                width: Style.space(20)
                height: Style.space(20)
                visible: parent.children[0].status !== Image.Ready
                text: (modelData.name || "?").charAt(0).toUpperCase()
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                font.bold: true
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                anchors.verticalCenter: parent.verticalCenter
              }

              Column {
                width: parent.width - Style.space(150)
                spacing: 2
                anchors.verticalCenter: parent.verticalCenter
                Text {
                  width: parent.width
                  text: modelData.name || modelData.id
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  font.bold: index === root.selectedIndex
                  elide: Text.ElideRight
                }
                Row {
                  spacing: Style.space(6)
                  Repeater {
                    model: uniqueCountries(modelData)
                    FlagIcon {
                      required property var modelData
                      country: modelData
                      pluginDir: root.pluginDir
                      width: 14
                      height: 10
                    }
                  }
                  Text {
                    text: connSummary(modelData)
                    color: Qt.darker(root.fg, 1.5)
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: Text.ElideRight
                  }
                }
                Canvas {
                  width: parent.width
                  height: 10
                  onPaint: {
                    var ctx = getContext("2d")
                    ctx.clearRect(0, 0, width, height)
                    var spark = modelData.spark || []
                    if (spark.length < 2)
                      return
                    var max = 1
                    var i
                    for (i = 0; i < spark.length; i++)
                      if (spark[i] > max) max = spark[i]
                    ctx.beginPath()
                    for (i = 0; i < spark.length; i++) {
                      var x = i / (spark.length - 1) * width
                      var y = height - (spark[i] / max) * (height - 1) - 0.5
                      if (i === 0) ctx.moveTo(x, y)
                      else ctx.lineTo(x, y)
                    }
                    ctx.strokeStyle = root.cssAccent()
                    ctx.lineWidth = 1.2
                    ctx.stroke()
                  }
                  Component.onCompleted: requestPaint()
                }
              }

              Text {
                visible: modelData.blocked
                text: modelData.mechanism === "endpoints" ? "endpoints" : "cgroup"
                color: root.accent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                anchors.verticalCenter: parent.verticalCenter
              }

              ToggleSwitch {
                checked: !!modelData.blocked
                enabled: root.canBlockApp(modelData)
                opacity: enabled ? 1 : 0.35
                foreground: root.fg
                anchors.verticalCenter: parent.verticalCenter
                onToggled: {
                  root.selectedIndex = index
                  if (root.canBlockApp(modelData) && root.liveSnitch)
                    root.liveSnitch.requestBlock(modelData.id)
                }
              }
            }
          }
        }

        Text {
          visible: !root.blockingReady
          width: parent.width
          text: root.blockHint || "Blocking uses nftables via polkit."
          color: Qt.darker(root.fg, 1.5)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Text {
          visible: root.lastBlockError !== "" && !root.confirmIps
          width: parent.width
          text: root.lastBlockError
          color: root.liveBar && root.liveBar.urgent ? root.liveBar.urgent : "#e25c5c"
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Rectangle {
          visible: root.confirmIps
          width: parent.width
          height: confirmCol.implicitHeight + Style.space(16)
          radius: Style.cornerRadius
          color: Style.hoverFillFor(root.fg, root.accent)
          border.color: root.accent
          border.width: 1

          Column {
            id: confirmCol
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.margins: Style.space(10)
            spacing: Style.space(8)
            Text {
              width: parent.width
              text: "Cgroup block failed. Fall back to endpoints only — affects all apps?"
              color: root.fg
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Text {
              width: parent.width
              text: root.lastBlockError
              color: Qt.darker(root.fg, 1.4)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
              visible: text !== ""
            }
            Row {
              spacing: Style.space(8)
              Button {
                text: "Cancel"
                foreground: root.fg
                fontFamily: root.fontFamily
                onClicked: {
                  root.confirmIps = false
                  if (root.liveSnitch)
                    root.liveSnitch.pendingIpsApp = ""
                }
              }
              Button {
                text: "Block endpoints"
                foreground: root.fg
                fontFamily: root.fontFamily
                onClicked: root.confirmIpsBlock()
              }
            }
          }
        }

        Text {
          width: parent.width
          text: "IP geolocation by DB-IP https://db-ip.com (CC-BY-4.0). Map: Natural Earth 110m, public domain. Arrows · b block · / search."
          color: Qt.darker(root.fg, 1.8)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }
      }
    }
  }

  function uniqueCountries(app) {
    var seen = {}
    var out = []
    var cs = (app && app.connections) || []
    for (var i = 0; i < cs.length; i++) {
      var cc = cs[i].country
      if (cc && !seen[cc]) {
        seen[cc] = true
        out.push(cc)
      }
      if (out.length >= 4)
        break
    }
    return out
  }

  function connSummary(app) {
    var n = (app && app.connections) ? app.connections.length : 0
    var u = app && app.unresolved ? app.unresolved : 0
    var s = n + (n === 1 ? " flow" : " flows")
    if (u)
      s += " · " + u + " UDP unresolved"
    return s
  }

  function cssAccent() {
    return "rgba(" + Math.round(root.accent.r * 255) + "," + Math.round(root.accent.g * 255) + "," + Math.round(root.accent.b * 255) + ",0.9)"
  }
}
