function emptyState() {
    return {
        revision: 0,
        hello: false,
        coverage: "TCP + connected UDP",
        rdns: false,
        connections: {},
        apps: {},
        ordered: [],
        count: 0,
        pulse: false,
        pulseNetwork: "",
        awayKeys: [],
        digestText: "",
        blocked: {},
        lastError: ""
    }
}

function cloneJson(v) {
    return JSON.parse(JSON.stringify(v))
}

function applyLine(state, line, now) {
    if (!state)
        state = emptyState()
    if (!line)
        return state
    var trimmed = String(line).replace(/^\s+|\s+$/g, "")
    if (!trimmed || trimmed.charAt(0) === "#")
        return state
    var ev
    try {
        ev = JSON.parse(trimmed)
    } catch (e) {
        state.lastError = "bad json"
        state.revision += 1
        return state
    }
    return applyEvent(state, ev, now || Date.now())
}

function applyEvent(state, ev, now) {
    if (!ev || !ev.type)
        return state
    if (ev.type === "hello") {
        state.hello = true
        state.coverage = ev.coverage === "tcp+connected-udp" ? "TCP + connected UDP" : (ev.coverage || state.coverage)
        state.rdns = ev.rdns === true
    } else if (ev.type === "snapshot") {
        state.connections = {}
        var list = ev.connections || []
        for (var i = 0; i < list.length; i++)
            putConnection(state, list[i], now, false)
        rebuild(state, now)
    } else if (ev.type === "connect") {
        putConnection(state, ev, now, true)
        rebuild(state, now)
    } else if (ev.type === "disconnect") {
        if (ev.id && state.connections[ev.id])
            delete state.connections[ev.id]
        rebuild(state, now)
    } else if (ev.type === "tick") {
        if (typeof ev.count === "number")
            state.count = ev.count
        sampleSparklines(state)
        state.revision += 1
    } else if (ev.type === "digest") {
        state.awayKeys = ev.keys || []
        var n = typeof ev.newNetworks === "number" ? ev.newNetworks : state.awayKeys.length
        state.digestText = digestLine(n)
        state.revision += 1
    } else if (ev.type === "status") {
        state.lastError = ev.message === "ok" ? "" : (ev.message || "")
        state.revision += 1
    }
    return state
}

function putConnection(state, raw, now, detectPulse) {
    var conn = normalizeConn(raw, now)
    if (!conn.id)
        return
    var isNew = !state.connections[conn.id]
    state.connections[conn.id] = conn
    if (detectPulse && isNew && conn.newNetwork && !conn.unresolved) {
        state.pulse = true
        state.pulseNetwork = conn.networkKey || conn.remote.ip
        if (state.awayKeys.indexOf(conn.networkKey) === -1 && conn.networkKey)
            state.awayKeys.push(conn.networkKey)
        state.digestText = digestLine(state.awayKeys.length)
    }
}

function normalizeConn(raw, now) {
    var app = raw.app || {}
    var local = raw.local || {}
    var remote = raw.remote || {}
    return {
        id: raw.id || "",
        proto: raw.proto || "tcp",
        inode: raw.inode || 0,
        app: {
            id: app.id || "unknown",
            name: app.name || app.id || "unknown",
            icon: app.icon || "",
            desktop: app.desktop || "",
            pid: app.pid || 0,
            system: app.system === true
        },
        local: { ip: local.ip || "", port: local.port || 0 },
        remote: { ip: remote.ip || "", port: remote.port || 0 },
        state: raw.state || "",
        country: raw.country || "",
        lat: typeof raw.lat === "number" ? raw.lat : 0,
        lon: typeof raw.lon === "number" ? raw.lon : 0,
        unresolved: raw.unresolved === true,
        newNetwork: raw.newNetwork === true,
        networkKey: raw.networkKey || networkKey(remote.ip || ""),
        seenAt: now || Date.now()
    }
}

function rebuild(state, now) {
    var apps = {}
    var ids = Object.keys(state.connections)
    for (var i = 0; i < ids.length; i++) {
        var c = state.connections[ids[i]]
        var aid = c.app.id || "unknown"
        if (!apps[aid]) {
            apps[aid] = {
                id: aid,
                name: c.app.name || aid,
                icon: c.app.icon || "",
                desktop: c.app.desktop || "",
                system: c.app.system === true,
                pids: [],
                connections: [],
                unresolved: 0,
                lastActivity: 0,
                spark: (state.apps[aid] && state.apps[aid].spark) ? state.apps[aid].spark.slice() : [],
                blocked: !!(state.blocked[aid]),
                mechanism: (state.blocked[aid] && state.blocked[aid].mechanism) || ""
            }
        }
        var a = apps[aid]
        a.connections.push(c)
        if (c.app.pid && a.pids.indexOf(c.app.pid) === -1)
            a.pids.push(c.app.pid)
        if (c.unresolved)
            a.unresolved += 1
        if (c.seenAt > a.lastActivity)
            a.lastActivity = c.seenAt
        if (c.app.name)
            a.name = c.app.name
        if (c.app.icon)
            a.icon = c.app.icon
    }
    // Preserve spark history for apps that dropped out this tick? No — gone apps leave.
    var ordered = []
    for (var k in apps)
        ordered.push(apps[k])
    ordered.sort(function (x, y) {
        if (y.lastActivity !== x.lastActivity)
            return y.lastActivity - x.lastActivity
        return String(x.name).localeCompare(String(y.name))
    })
    state.apps = apps
    state.ordered = ordered
    state.count = ids.length
    state.revision += 1
    return state
}

function sampleSparklines(state) {
    var k
    for (k in state.apps) {
        var a = state.apps[k]
        if (!a.spark)
            a.spark = []
        a.spark.push(a.connections.length)
        if (a.spark.length > 24)
            a.spark.shift()
    }
}

function digestLine(n) {
    if (!n)
        return ""
    if (n === 1)
        return "1 new network while you were away"
    return n + " new networks while you were away"
}

function markLooked(state) {
    state.awayKeys = []
    state.digestText = ""
    state.pulse = false
    state.revision += 1
    return state
}

function clearPulse(state) {
    state.pulse = false
    state.pulseNetwork = ""
    state.revision += 1
    return state
}

function setBlocked(state, appId, mechanism) {
    if (!state.blocked)
        state.blocked = {}
    if (mechanism) {
        state.blocked[appId] = { mechanism: mechanism }
        if (state.apps[appId]) {
            state.apps[appId].blocked = true
            state.apps[appId].mechanism = mechanism
        }
    } else {
        delete state.blocked[appId]
        if (state.apps[appId]) {
            state.apps[appId].blocked = false
            state.apps[appId].mechanism = ""
        }
    }
    state.revision += 1
    return state
}

function isBlockable(app) {
    if (!app)
        return false
    if (app.system === true)
        return false
    var id = String(app.id || "").toLowerCase()
    if (id === "system" || id === "unknown" || id === "")
        return false
    return true
}

function anyBlocked(state) {
    if (!state || !state.blocked)
        return false
    for (var k in state.blocked)
        return true
    return false
}

function filterApps(ordered, query) {
    if (!query)
        return ordered || []
    var q = String(query).toLowerCase()
    var out = []
    var list = ordered || []
    for (var i = 0; i < list.length; i++) {
        var a = list[i]
        var blob = (a.name + " " + a.id + " " + countryBlob(a)).toLowerCase()
        if (blob.indexOf(q) !== -1)
            out.push(a)
    }
    return out
}

function countryBlob(app) {
    var s = ""
    var cs = app.connections || []
    for (var i = 0; i < cs.length; i++) {
        if (cs[i].country)
            s += " " + cs[i].country
        if (cs[i].remote && cs[i].remote.ip)
            s += " " + cs[i].remote.ip
    }
    return s
}

function drawableArcs(connections, origin, cap) {
    cap = cap || 40
    var list = []
    var ids = Object.keys(connections || {})
    for (var i = 0; i < ids.length; i++) {
        var c = connections[ids[i]]
        if (!c || c.unresolved)
            continue
        if (!c.country)
            continue
        if (c.lat === 0 && c.lon === 0)
            continue
        list.push(c)
    }
    list.sort(function (a, b) { return (b.seenAt || 0) - (a.seenAt || 0) })
    if (list.length > cap)
        list = list.slice(0, cap)
    return list
}

function networkKey(ip) {
    if (!ip)
        return ""
    if (ip.indexOf(":") === -1) {
        var p = ip.split(".")
        if (p.length !== 4)
            return ip
        return p[0] + "." + p[1] + "." + p[2] + ".0/24"
    }
    // Mapped v4
    var mapped = ip.toLowerCase()
    var idx = mapped.lastIndexOf(":")
    if (mapped.indexOf(".") !== -1 && mapped.indexOf(":ffff:") !== -1) {
        var v4 = mapped.split(":").pop()
        return networkKey(v4)
    }
    var parts = expandV6(ip)
    if (!parts)
        return ip + "/48"
    return parts[0] + ":" + parts[1] + ":" + parts[2] + "::/48"
}

function expandV6(ip) {
    var s = String(ip).split("%")[0]
    if (s.charAt(0) === "[" )
        s = s.substring(1, s.length - 1)
    var halves = s.split("::")
    var head = halves[0] ? halves[0].split(":") : []
    var tail = halves.length > 1 && halves[1] ? halves[1].split(":") : []
    var miss = 8 - (head.length + tail.length)
    if (miss < 0)
        return null
    var full = []
    var i
    for (i = 0; i < head.length; i++)
        full.push(head[i] || "0")
    for (i = 0; i < miss; i++)
        full.push("0")
    for (i = 0; i < tail.length; i++)
        full.push(tail[i] || "0")
    if (full.length !== 8)
        return null
    return full
}

function pidsOf(app) {
    return (app && app.pids) ? app.pids : []
}

function remotesOf(app) {
    var out = []
    if (!app)
        return out
    var cs = app.connections || []
    for (var i = 0; i < cs.length; i++) {
        if (cs[i].unresolved)
            continue
        var ip = cs[i].remote && cs[i].remote.ip
        if (ip && out.indexOf(ip) === -1)
            out.push(ip)
    }
    return out
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        emptyState: emptyState,
        applyLine: applyLine,
        applyEvent: applyEvent,
        networkKey: networkKey,
        digestLine: digestLine,
        filterApps: filterApps,
        drawableArcs: drawableArcs,
        markLooked: markLooked,
        setBlocked: setBlocked,
        isBlockable: isBlockable,
        anyBlocked: anyBlocked,
        remotesOf: remotesOf,
        rebuild: rebuild
    }
}
