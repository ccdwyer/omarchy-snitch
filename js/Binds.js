.pragma library

// Detect live Hyprland binds and plan a bindings.lua snippet.
// Never auto-applied — installBinds runs only after an explicit click.

var PLUGIN_ID = "io.github.chris.snitch"
var SUPER = 64
var SHIFT = 1
var CTRL = 4
var ALT = 8

var CANDIDATES = [
    {
        keys: "SUPER + ALT + S",
        modmask: SUPER + ALT,
        key: "S",
        desc: "Snitch",
        cmd: "omarchy-shell shell toggle io.github.chris.snitch '{}'",
        alternates: [
            { keys: "SUPER + SHIFT + ALT + S", modmask: SUPER + SHIFT + ALT, key: "S" }
        ]
    }
]

var offer = {
    needed: true,
    note: "",
    installed: 0,
    toAdd: [],
    skipped: []
}

function setOffer(next) {
    offer = next || offer
}

function parseBinds(raw) {
    if (!raw)
        return []
    var data = raw
    if (typeof raw === "string") {
        try {
            data = JSON.parse(raw)
        } catch (e) {
            return []
        }
    }
    return data && data.length ? data : []
}

function keyOf(bind) {
    return String((bind && bind.key) || "").toUpperCase()
}

function keysMatch(a, b) {
    var x = String(a || "").toUpperCase()
    var y = String(b || "").toUpperCase()
    if (x === y)
        return true
    function isPeriod(k) { return k === "PERIOD" || k === "." }
    return isPeriod(x) && isPeriod(y)
}

function isOurs(bind) {
    if (!bind)
        return false
    var arg = String(bind.arg || "")
    var desc = String(bind.description || "")
    if (arg.indexOf(PLUGIN_ID) >= 0)
        return true
    for (var i = 0; i < CANDIDATES.length; i++) {
        if (desc === CANDIDATES[i].desc)
            return true
    }
    return false
}

function oursCount(binds) {
    var n = 0
    var list = binds || []
    for (var i = 0; i < list.length; i++) {
        if (isOurs(list[i]))
            n++
    }
    return n
}

function comboOwner(binds, modmask, key) {
    var want = String(key || "").toUpperCase()
    var list = binds || []
    for (var i = 0; i < list.length; i++) {
        var b = list[i]
        if (Number(b.modmask) !== Number(modmask))
            continue
        if (!keysMatch(keyOf(b), want))
            continue
        if (isOurs(b))
            return { ours: true, desc: String(b.description || "") }
        return { ours: false, desc: String(b.description || b.dispatcher || "already bound") }
    }
    return null
}

function pickCombo(binds, candidate) {
    var owner = comboOwner(binds, candidate.modmask, candidate.key)
    if (!owner)
        return { keys: candidate.keys, modmask: candidate.modmask, key: candidate.key, desc: candidate.desc, cmd: candidate.cmd, chosen: candidate.keys }
    if (owner.ours)
        return { already: true, keys: candidate.keys, desc: candidate.desc }
    var alts = candidate.alternates || []
    for (var i = 0; i < alts.length; i++) {
        var a = alts[i]
        if (!comboOwner(binds, a.modmask, a.key))
            return {
                keys: a.keys,
                modmask: a.modmask,
                key: a.key,
                desc: candidate.desc,
                cmd: candidate.cmd,
                chosen: a.keys,
                preferred: candidate.keys,
                conflict: owner.desc
            }
    }
    return { skipped: true, keys: candidate.keys, desc: candidate.desc, conflict: owner.desc }
}

function plan(binds) {
    var toAdd = []
    var skipped = []
    var already = 0
    for (var i = 0; i < CANDIDATES.length; i++) {
        var pick = pickCombo(binds, CANDIDATES[i])
        if (pick.already)
            already++
        else if (pick.skipped)
            skipped.push(pick)
        else
            toAdd.push(pick)
    }
    var liveOurs = oursCount(binds)
    if (liveOurs > 0)
        already = Math.max(already, liveOurs)
    var needed = already === 0
    if (!needed)
        toAdd = []
    var note = ""
    if (!needed)
        note = ""
    else if (!toAdd.length && skipped.length)
        note = skipped.map(function(s) { return s.keys + " is " + (s.conflict || "taken") }).join("; ")
    else if (toAdd.length) {
        var bits = toAdd.map(function(p) { return p.chosen || p.keys })
        note = "Set " + bits.join(", ")
        for (var s = 0; s < skipped.length; s++)
            note += " — skipped " + skipped[s].keys + " (" + skipped[s].conflict + ")"
    }
    return { needed: needed, already: already, toAdd: toAdd, skipped: skipped, note: note }
}

function luaLine(item) {
    var keys = String(item.chosen || item.keys || "").replace(/"/g, "")
    var desc = String(item.desc || "").replace(/"/g, "")
    var cmd = String(item.cmd || "").replace(/"/g, '\\"')
    return "o.bind(\"" + keys + "\", \"" + desc + "\", \"" + cmd + "\")"
}

function luaBlock(items) {
    var lines = []
    var list = items || []
    for (var i = 0; i < list.length; i++)
        lines.push(luaLine(list[i]))
    return lines.join("\n")
}

function applyScan(raw) {
    var p = plan(parseBinds(raw))
    setOffer(p)
    return p
}

function notifyBody(items, skipped) {
    var lines = []
    var list = items || []
    for (var i = 0; i < list.length; i++) {
        var it = list[i]
        lines.push((it.chosen || it.keys) + " — " + it.desc)
    }
    var miss = skipped || []
    for (var s = 0; s < miss.length; s++)
        lines.push("skipped " + miss[s].keys + " (" + (miss[s].conflict || "taken") + ")")
    return lines.join("\n")
}

function notifyArgv(appName, headline, body) {
    return ["omarchy", "notification", "send", "--app-name", String(appName || PLUGIN_ID), "-g", "󰌌", String(headline || "Keybindings"), String(body || "")]
}
