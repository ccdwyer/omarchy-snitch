#!/usr/bin/env python3
"""Append or replace a marked o.bind block in ~/.config/hypr/bindings.lua.

Only invoked after an explicit Set hotkey click — never on plugin load.
"""

import os
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: install-binds.py PLUGIN_ID LUA_BLOCK", file=sys.stderr)
        return 2
    plugin_id = sys.argv[1]
    block = sys.argv[2]
    if not block.endswith("\n"):
        block += "\n"
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    path = os.path.join(config_home, "hypr", "bindings.lua")
    begin = f"-- BEGIN {plugin_id}"
    end = f"-- END {plugin_id}"
    chunk = f"{begin}\n{block}{end}\n"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    if begin in text and end in text:
        pre = text[: text.index(begin)]
        post = text[text.index(end) + len(end) :].lstrip("\n")
        text = pre.rstrip() + "\n\n" + chunk
        if post:
            text = text.rstrip() + "\n" + post
            if not text.endswith("\n"):
                text += "\n"
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text = text.rstrip() + "\n\n" + chunk
        if not text.endswith("\n"):
            text += "\n"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
