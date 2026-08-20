// Equirectangular projection. Map space is 360×180, x = lon+180, y = 90-lat.

function project(lon, lat, width, height) {
    return {
        x: ((lon + 180) / 360) * width,
        y: ((90 - lat) / 180) * height
    }
}

function unproject(x, y, width, height) {
    return {
        lon: (x / width) * 360 - 180,
        lat: 90 - (y / height) * 180
    }
}

function controlPoint(x0, y0, x1, y1, bulge) {
    var mx = (x0 + x1) / 2
    var my = (y0 + y1) / 2
    var dx = x1 - x0
    var dy = y1 - y0
    var len = Math.sqrt(dx * dx + dy * dy) || 1
    var nx = -dy / len
    var ny = dx / len
    var amp = (bulge === undefined ? 0.18 : bulge) * len
    // Always bow "up" on the map (smaller y).
    if (ny > 0) {
        nx = -nx
        ny = -ny
    }
    return { x: mx + nx * amp, y: my + ny * amp }
}

function timezoneOrigin(tz) {
    var table = {
        "America/New_York": [40.71, -74.01],
        "America/Chicago": [41.88, -87.63],
        "America/Denver": [39.74, -104.99],
        "America/Los_Angeles": [34.05, -118.24],
        "America/Phoenix": [33.45, -112.07],
        "America/Toronto": [43.65, -79.38],
        "America/Vancouver": [49.28, -123.12],
        "America/Sao_Paulo": [-23.55, -46.63],
        "America/Mexico_City": [19.43, -99.13],
        "America/New_York": [40.71, -74.01],
        "America/Detroit": [42.33, -83.05],
        "America/Indiana/Indianapolis": [39.77, -86.16],
        "America/New_York": [40.71, -74.01],
        "US/Eastern": [40.71, -74.01],
        "US/Central": [41.88, -87.63],
        "US/Pacific": [34.05, -118.24],
        "America/New_York": [40.71, -74.01],
        "Europe/London": [51.51, -0.13],
        "Europe/Paris": [48.86, 2.35],
        "Europe/Berlin": [52.52, 13.41],
        "Europe/Amsterdam": [52.37, 4.90],
        "Europe/Stockholm": [59.33, 18.07],
        "Europe/Oslo": [59.91, 10.75],
        "Europe/Helsinki": [60.17, 24.94],
        "Europe/Madrid": [40.42, -3.70],
        "Europe/Rome": [41.90, 12.50],
        "Europe/Warsaw": [52.23, 21.01],
        "Europe/Prague": [50.08, 14.44],
        "Europe/Vienna": [48.21, 16.37],
        "Europe/Zurich": [47.38, 8.54],
        "Europe/Lisbon": [38.72, -9.14],
        "Europe/Dublin": [53.35, -6.26],
        "Europe/Athens": [37.98, 23.73],
        "Europe/Istanbul": [41.01, 28.98],
        "Europe/Moscow": [55.76, 37.62],
        "Africa/Cairo": [30.04, 31.24],
        "Africa/Johannesburg": [-26.20, 28.04],
        "Africa/Lagos": [6.52, 3.38],
        "Africa/Nairobi": [-1.29, 36.82],
        "Asia/Tokyo": [35.68, 139.69],
        "Asia/Seoul": [37.57, 126.98],
        "Asia/Shanghai": [31.23, 121.47],
        "Asia/Hong_Kong": [22.32, 114.17],
        "Asia/Singapore": [1.35, 103.82],
        "Asia/Kolkata": [22.57, 88.36],
        "Asia/Calcutta": [22.57, 88.36],
        "Asia/Dubai": [25.20, 55.27],
        "Asia/Jakarta": [-6.21, 106.85],
        "Asia/Bangkok": [13.76, 100.50],
        "Asia/Taipei": [25.03, 121.57],
        "Australia/Sydney": [-33.87, 151.21],
        "Australia/Melbourne": [-37.81, 144.96],
        "Pacific/Auckland": [-36.85, 174.76],
        "UTC": [0, 0]
    }
    if (tz && table[tz])
        return { lat: table[tz][0], lon: table[tz][1] }
    // Guess from a suffix.
    if (tz) {
        if (tz.indexOf("Stockholm") !== -1) return { lat: 59.33, lon: 18.07 }
        if (tz.indexOf("London") !== -1) return { lat: 51.51, lon: -0.13 }
        if (tz.indexOf("Pacific") !== -1) return { lat: 34.05, lon: -118.24 }
        if (tz.indexOf("Eastern") !== -1 || tz.indexOf("New_York") !== -1) return { lat: 40.71, lon: -74.01 }
    }
    return { lat: 48.0, lon: 10.0 }
}

function flagUrl(pluginDir, cc) {
    if (!cc)
        return ""
    var code = String(cc).toUpperCase()
    if (!pluginDir)
        return ""
    return "file://" + pluginDir + "/data/flags/" + code + ".svg"
}

function pointOnQuad(x0, y0, cx, cy, x1, y1, t) {
    var u = 1 - t
    return {
        x: u * u * x0 + 2 * u * t * cx + t * t * x1,
        y: u * u * y0 + 2 * u * t * cy + t * t * y1
    }
}

function hitArc(px, py, x0, y0, cx, cy, x1, y1, thresh) {
    thresh = thresh || 8
    var t
    for (t = 0; t <= 1.001; t += 0.05) {
        var p = pointOnQuad(x0, y0, cx, cy, x1, y1, t)
        var dx = p.x - px
        var dy = p.y - py
        if (dx * dx + dy * dy <= thresh * thresh)
            return true
    }
    return false
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        project: project,
        unproject: unproject,
        controlPoint: controlPoint,
        timezoneOrigin: timezoneOrigin,
        hitArc: hitArc,
        pointOnQuad: pointOnQuad
    }
}
