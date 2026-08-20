import QtQuick
import QtQuick.Shapes
import Quickshell.Io
import "Geo.js" as Geo

Item {
  id: root
  property string pluginDir: ""
  property string worldDataPath: pluginDir ? pluginDir + "/data/world-paths.json" : ""
  property var arcs: []
  property var origin: ({ lat: 48.0, lon: 10.0 })
  property color landColor: "#2a3340"
  property color borderColor: "#4a5564"
  property color oceanColor: "#12161c"
  property color accentColor: "#e2a84b"
  property color dimColor: "#8899aa"
  property var hoverArc: null
  property int phase: 0

  readonly property string combinedPath: pathData
  property string pathData: fallbackPath
  property int extraHidden: 0

  // Quiet empty-ocean outline so a missing JSON file still paints a globe.
  readonly property string fallbackPath: "M40,70 L80,55 L120,72 L150,60 L175,78 L130,95 L90,88 Z M190,68 L230,55 L270,70 L255,95 L210,92 Z M40,110 L90,105 L140,125 L95,140 L50,130 Z M200,115 L250,108 L300,125 L260,145 L210,138 Z M300,55 L340,48 L350,70 L320,78 Z"

  FileView {
    id: worldFile
    path: root.worldDataPath
    watchChanges: false
    printErrors: false
    onLoaded: root.ingestWorld(text())
  }

  function ingestWorld(raw) {
    try {
      var data = JSON.parse(raw)
      var list = data.paths || []
      var s = ""
      for (var i = 0; i < list.length; i++)
        s += list[i]
      if (s.length > 20)
        root.pathData = s
    } catch (e) { }
  }

  Component.onCompleted: {
    if (worldFile.text && worldFile.text())
      ingestWorld(worldFile.text())
    else if (worldDataPath)
      worldFile.reload()
  }

  Rectangle {
    anchors.fill: parent
    color: root.oceanColor
    radius: 6
  }

  // Continents are the Shape below (Natural Earth paths). Canvas only paints arcs.
  Item {
    id: landHost
    width: 360
    height: 180
    transformOrigin: Item.TopLeft
    transform: Scale {
      xScale: root.width > 0 ? root.width / 360 : 1
      yScale: root.height > 0 ? root.height / 180 : 1
    }

    Shape {
      id: land
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      ShapePath {
        fillColor: root.landColor
        strokeColor: root.borderColor
        strokeWidth: 0.7
        fillRule: ShapePath.OddEvenFill
        PathSvg { path: root.pathData }
      }
    }
  }

  function css(c, a) {
    if (!c)
      return "rgba(226,168,75," + a + ")"
    return "rgba(" + Math.round(c.r * 255) + "," + Math.round(c.g * 255) + "," + Math.round(c.b * 255) + "," + a + ")"
  }

  Canvas {
    id: canvas
    anchors.fill: parent
    antialiasing: true
    renderTarget: Canvas.FramebufferObject
    onPaint: {
      var ctx = getContext("2d")
      var w = width
      var h = height
      ctx.clearRect(0, 0, w, h)
      drawArcs(ctx, w, h)
      drawOrigin(ctx, w, h)
    }
  }

  function drawArcs(ctx, w, h) {
    var list = root.arcs || []
    var o = Geo.project(root.origin.lon, root.origin.lat, w, h)
    var i
    for (i = 0; i < list.length; i++) {
      var c = list[i]
      var p = Geo.project(c.lon, c.lat, w, h)
      var ctl = Geo.controlPoint(o.x, o.y, p.x, p.y, 0.22)
      var hovered = root.hoverArc && root.hoverArc.id === c.id
      var t = ((root.phase + i * 17) % 100) / 100
      ctx.beginPath()
      ctx.moveTo(o.x, o.y)
      ctx.quadraticCurveTo(ctl.x, ctl.y, p.x, p.y)
      ctx.strokeStyle = root.css(root.accentColor, hovered ? 0.55 : 0.22)
      ctx.lineWidth = hovered ? 6 : 4
      ctx.stroke()
      ctx.beginPath()
      ctx.moveTo(o.x, o.y)
      ctx.quadraticCurveTo(ctl.x, ctl.y, p.x, p.y)
      ctx.strokeStyle = root.css(root.accentColor, hovered ? 1 : 0.9)
      ctx.lineWidth = hovered ? 2.4 : 1.4
      ctx.stroke()
      var bead = Geo.pointOnQuad(o.x, o.y, ctl.x, ctl.y, p.x, p.y, t)
      ctx.beginPath()
      ctx.arc(bead.x, bead.y, hovered ? 3.2 : 2.1, 0, Math.PI * 2)
      ctx.fillStyle = "#fff6d8"
      ctx.fill()
    }
  }

  function drawOrigin(ctx, w, h) {
    var o = Geo.project(root.origin.lon, root.origin.lat, w, h)
    ctx.beginPath()
    ctx.arc(o.x, o.y, 4.5, 0, Math.PI * 2)
    ctx.fillStyle = root.accentColor
    ctx.fill()
    ctx.beginPath()
    ctx.arc(o.x, o.y, 8, 0, Math.PI * 2)
    ctx.strokeStyle = root.css(root.accentColor, 0.45)
    ctx.lineWidth = 1.2
    ctx.stroke()
  }

  Timer {
    interval: 40
    running: root.visible && root.arcs && root.arcs.length > 0
    repeat: true
    onTriggered: {
      root.phase = (root.phase + 2) % 100
      canvas.requestPaint()
    }
  }

  onArcsChanged: canvas.requestPaint()
  onWidthChanged: canvas.requestPaint()
  onHeightChanged: canvas.requestPaint()
  onOriginChanged: canvas.requestPaint()
  onHoverArcChanged: canvas.requestPaint()
  onAccentColorChanged: canvas.requestPaint()

  MouseArea {
    anchors.fill: parent
    hoverEnabled: true
    onPositionChanged: function(mouse) {
      root.hoverArc = root.hit(mouse.x, mouse.y)
    }
    onExited: root.hoverArc = null
  }

  function hit(px, py) {
    var list = root.arcs || []
    var o = Geo.project(root.origin.lon, root.origin.lat, width, height)
    for (var i = 0; i < list.length; i++) {
      var c = list[i]
      var p = Geo.project(c.lon, c.lat, width, height)
      var ctl = Geo.controlPoint(o.x, o.y, p.x, p.y, 0.22)
      if (Geo.hitArc(px, py, o.x, o.y, ctl.x, ctl.y, p.x, p.y, 9))
        return c
    }
    return null
  }

  Text {
    anchors.left: parent.left
    anchors.bottom: parent.bottom
    anchors.margins: 8
    visible: extraHidden > 0
    text: "+" + extraHidden + " more"
    color: root.dimColor
    font.pixelSize: 11
  }
}
