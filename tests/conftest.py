"""Stand-ins for the age and age-plugin-yubikey binaries, so the tests need no YubiKey and no real age.

The fake YubiKeys live in a JSON state file: which serials are plugged in and their age identities.
Fake age "ciphertext" is a header naming the recipients, then the plaintext. A recipient age1yubikey1<tag>
matches the stub AGE-PLUGIN-YUBIKEY-<TAG>.
"""
import json
import os
import stat
import sys
import textwrap

import pytest

import yubi_deployers

FAKE_PLUGIN = r'''
import json, os, sys
state_path = os.environ["FAKE_YK_STATE"]
state = json.load(open(state_path))
args = sys.argv[1:]
calls = state.setdefault("calls", [])
calls.append(args)

def block(serial, ident):
    return (f"#       Serial: {serial}, Slot: {ident['slot']}\n"
            f"#         Name: eth deployer\n"
            f"#      Created: Thu, 12 Nov 2026 21:00:00 +0000\n"
            f"#   PIN policy: {ident['pin']}  (text)\n"
            f"# Touch policy: {ident['touch']} (text)\n"
            f"#    Recipient: age1yubikey1{ident['tag'].lower()}\n"
            f"AGE-PLUGIN-YUBIKEY-{ident['tag'].upper()}\n")

plugged = [s for s in state["plugged"]]
if "--identity" in args:
    serial = int(args[args.index("--serial") + 1]) if "--serial" in args else None
    for s in plugged:
        if serial is None or s == serial:
            for ident in state["keys"][str(s)]:
                print(block(s, ident))
elif "--generate" in args:
    if len(plugged) != 1:
        print("Multiple YubiKeys are plugged in" if plugged else "no YubiKey", file=sys.stderr)
        json.dump(state, open(state_path, "w")); sys.exit(1)
    s = plugged[0]
    idents = state["keys"][str(s)]
    ident = {"slot": len(idents) + 1, "pin": args[args.index("--pin-policy") + 1].capitalize(),
             "touch": args[args.index("--touch-policy") + 1].capitalize(), "tag": f"S{s}X{len(idents) + 1}"}
    idents.append(ident)
    print(block(s, ident))
json.dump(state, open(state_path, "w"))
'''

FAKE_AGE = r'''
import json, os, sys
state = json.load(open(os.environ["FAKE_YK_STATE"]))
args = sys.argv[1:]
if args[0] == "-d":
    stubs = [l.strip() for l in sys.stdin.read().splitlines() if l.strip()]
    data = open(args[-1], "rb").read()
    header, _, payload = data.partition(b"\n")
    recipients = header.decode().split(" ", 1)[1].split(",")
    if os.environ.get("FAKE_AGE_PARTIAL"):
        sys.stdout.buffer.write(payload[: len(payload) // 2]); sys.exit(1)
    plugged_tags = {i["tag"].upper() for s in state["plugged"] for i in state["keys"][str(s)]}
    for stub in stubs:
        tag = stub.removeprefix("AGE-PLUGIN-YUBIKEY-")
        if "age1yubikey1" + tag.lower() in recipients and tag in plugged_tags:
            sys.stdout.buffer.write(payload); sys.exit(0)
    print("age: error: no identity matched any of the recipients", file=sys.stderr); sys.exit(1)
recipients = [args[i + 1] for i, a in enumerate(args) if a == "-r"]
sys.stdout.buffer.write(("FAKEAGE " + ",".join(recipients) + "\n").encode() + sys.stdin.buffer.read())
'''


class FakeYubiKeys:
    def __init__(self, path):
        self.path = path

    def load(self):
        return json.loads(self.path.read_text())

    def save(self, state):
        self.path.write_text(json.dumps(state))

    def plug(self, *serials):
        state = self.load()
        state["plugged"] = list(serials)
        self.save(state)

    def add(self, serial, *idents):
        state = self.load()
        state["keys"].setdefault(str(serial), []).extend(idents)
        self.save(state)

    @property
    def calls(self):
        return self.load().get("calls", [])

    @property
    def keys(self):
        return self.load()["keys"]


@pytest.fixture
def yubikeys(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("age-plugin-yubikey", FAKE_PLUGIN), ("age", FAKE_AGE)):
        exe = bin_dir / name
        exe.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    state = tmp_path / "yubikeys.json"
    state.write_text(json.dumps({"plugged": [], "keys": {"111": [], "222": []}}))
    monkeypatch.setenv("FAKE_YK_STATE", str(state))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    key_dir = tmp_path / "eth"
    monkeypatch.setattr(yubi_deployers, "KEY_DIR", key_dir)
    return FakeYubiKeys(state)
