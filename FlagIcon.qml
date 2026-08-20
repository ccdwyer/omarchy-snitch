import QtQuick

Item {
  id: root
  property string country: ""
  property string pluginDir: ""
  property color fallbackFill: "#445566"
  property color textColor: "#ffffff"
  implicitWidth: 18
  implicitHeight: 12

  readonly property string code: String(country || "").toUpperCase()
  readonly property string svgPath: (pluginDir && code.length === 2)
    ? "file://" + pluginDir + "/data/flags/" + code + ".svg"
    : ""

  Image {
    id: img
    anchors.fill: parent
    source: root.svgPath
    fillMode: Image.PreserveAspectFit
    asynchronous: true
    visible: status === Image.Ready
    smooth: true
  }

  Rectangle {
    anchors.fill: parent
    visible: !img.visible
    color: root.fallbackFill
    border.color: Qt.rgba(textColor.r, textColor.g, textColor.b, 0.25)
    border.width: 1
    radius: 1

    Text {
      anchors.centerIn: parent
      text: root.code || "?"
      color: root.textColor
      font.pixelSize: Math.max(7, Math.round(root.height * 0.7))
      font.bold: true
    }
  }
}
