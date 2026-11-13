"""One-time setup: put an Ethereum private key behind your YubiKeys (touch, then a keystore password).

    uv run scripts/setup_key.py                  # paste the private key at the hidden prompt
    uv run scripts/setup_key.py --yubikeys 1     # only one YubiKey at hand: no backup YubiKey

Order: the pasted key is checked and its address shown; you choose a keystore password (typed twice) and the key is
encrypted into a standard eth keystore (scrypt), which must decrypt back to the same key; then each YubiKey gets, or
reuses, an age identity with touch Always and PIN Never; the keystore is encrypted to all of them into a staging file;
each YubiKey alone must decrypt it back to the same bytes; only then is it published as
~/.config/eth/<address>.json.age, never over an existing file. The private key itself is never written to disk.
Needs: brew install age age-plugin-yubikey
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from eth_account import Account

from yubi_deployers import (STUB_PREFIX, LoadError, age_decrypt, decrypt_keystore, key_path,
                            read_password, yubikey_stubs)

SCRYPT_N = 2**21  # about 4-5 seconds per decrypt
PLUG_WAIT = 20  # seconds to wait for a YubiKey to appear after Enter
PASTE_MARKERS = ("\x1b[200~", "\x1b[201~")  # a terminal in bracketed-paste mode wraps a paste in these


class SetupError(Exception):
    pass


def read_private_key() -> bytes:
    """Hidden prompt (no echo, or it stops). An error never shows what was typed."""
    text = read_password("Private key (hidden; paste it, then press Enter): ")
    for marker in PASTE_MARKERS:
        text = text.replace(marker, "")
    text = text.strip()
    m = re.fullmatch(r"(?:0[xX])?([0-9a-fA-F]{64})", text)
    if not m:
        raise SetupError(f"not a private key: expected 64 hex digits, with or without 0x (got {len(text)} characters)")
    key = bytes.fromhex(m[1])
    try:
        Account.from_key(key)
    except ValueError:  # zero, or not below the secp256k1 group order
        raise SetupError("not a valid private key: the number is out of range") from None
    return key


def make_keystore(key: bytes) -> bytes:
    """A standard eth keystore for this key, under a new password; proven to decrypt back to the same key."""
    password = read_password("New keystore password: ")
    if not password:
        raise SetupError("empty password")
    if read_password("Same password again: ") != password:
        raise SetupError("the passwords differ")
    print("encrypting the keystore (scrypt, a few seconds)...")
    keystore = json.dumps(Account.encrypt(key, password, kdf="scrypt", iterations=SCRYPT_N)).encode()
    if decrypt_keystore(keystore, password).key != key:
        raise SetupError("the keystore did not decrypt back to the pasted key")
    return keystore


def parse_identities(text: str) -> list[dict]:
    """Identity blocks printed by age-plugin-yubikey --identity / --generate: metadata comments, then the stub."""
    found, cur = [], {}
    for line in (raw.strip() for raw in text.splitlines()):
        if m := re.match(r"#\s+Serial: (\d+), Slot: (\d+)", line):
            cur = {"serial": int(m[1]), "slot": int(m[2])}
        elif m := re.match(r"#\s+PIN policy: (\w+)", line):
            cur["pin"] = m[1]
        elif m := re.match(r"#\s+Touch policy: (\w+)", line):
            cur["touch"] = m[1]
        elif m := re.match(r"#\s+Recipient: (age1yubikey1\w+)", line):
            cur["recipient"] = m[1]
        elif line.startswith(STUB_PREFIX):
            if {"serial", "pin", "touch", "recipient"} <= cur.keys():
                found.append({**cur, "stub": line})
            cur = {}
    return found


def plugin(*args: str) -> str:
    """age-plugin-yubikey with stdout captured; its prompts (PIN, touch) use the terminal."""
    r = subprocess.run(["age-plugin-yubikey", *args], stdout=subprocess.PIPE, text=True)
    if r.returncode != 0:
        raise SetupError(f"age-plugin-yubikey {' '.join(args)} failed (if it said \"other connections outstanding\","
                         " quit Yubico Authenticator and run setup again)")
    return r.stdout


def setup_yubikey(i: int, n: int, taken: set[int]) -> dict:
    """Reuse a touch-Always, PIN-Never identity on the plugged-in YubiKey, or create one in a free slot."""
    input(f"\nPlug in YubiKey {i} of {n} only (unplug the others), then press Enter ")
    ids = parse_identities(plugin("--identity"))
    serials = {x["serial"] for x in ids}
    if len(serials) > 1:
        raise SetupError(f"several YubiKeys are plugged in ({sorted(serials)}); leave only one")
    if serials & taken:
        raise SetupError(f"YubiKey {serials.pop()} is already set up as an earlier one; plug in another")
    good = [x for x in ids if x["pin"] == "Never" and x["touch"] == "Always"]
    if good:
        ident = good[0]
        print(f"reusing slot {ident['slot']} of YubiKey {ident['serial']} (touch Always, PIN Never)")
    else:
        print("creating an age identity (touch Always, PIN Never) in a free slot;"
              " the YubiKey asks for its PIV PIN once (setup only), then a touch")
        try:
            made = parse_identities(plugin("--generate", "--pin-policy", "never", "--touch-policy", "always",
                                           "--name", "eth deployer"))
        except SetupError:
            raise SetupError("age-plugin-yubikey --generate failed (its reason is above). \"size error\": the PIV PIN"
                             " has 6 to 8 characters and is not the FIDO PIN; the factory one is 123456. A management"
                             " key error on firmware 5.7+: first run"
                             " ykman piv access change-management-key -a TDES --protect") from None
        if len(made) != 1:
            raise SetupError("could not read the identity age-plugin-yubikey created")
        ident = made[0]
        if ident["serial"] in taken:
            raise SetupError(f"YubiKey {ident['serial']} is already set up as an earlier one")
    if (ident["pin"], ident["touch"]) != ("Never", "Always"):
        raise SetupError(f"YubiKey {ident['serial']} slot {ident['slot']} has the wrong policies")
    return ident


def encrypt_to_staging(keystore: bytes, recipients: list[str], fd: int) -> None:
    """age -r ... into the staging file; only age's ciphertext touches disk."""
    with os.fdopen(fd, "wb") as f:
        r = subprocess.run(["age", *[a for rec in recipients for a in ("-r", rec)]], input=keystore, stdout=f)
        f.flush()
        os.fsync(f.fileno())
    if r.returncode != 0:
        raise SetupError("age could not encrypt to the YubiKeys")


def verify_alone(staging, keystore: bytes, ident: dict) -> None:
    """Only this YubiKey's stub is given to age, so only this YubiKey can decrypt."""
    input(f"\nLeave only YubiKey {ident['serial']} plugged in, press Enter, then touch it ")
    deadline = time.monotonic() + PLUG_WAIT  # macOS needs a moment to show a freshly plugged YubiKey
    while ident["stub"] not in yubikey_stubs(ident["serial"]):
        if time.monotonic() >= deadline:
            raise SetupError(f"YubiKey {ident['serial']} slot {ident['slot']} is not plugged in")
        time.sleep(0.5)
    if age_decrypt(staging, [ident["stub"]]) != keystore:
        raise SetupError(f"YubiKey {ident['serial']} decrypted different bytes")
    print(f"YubiKey {ident['serial']} decrypts it")


def publish(staging, target) -> None:
    """A hard link fails if the target exists, so an existing key file is never replaced."""
    try:
        os.link(staging, target)
    except FileExistsError:
        raise SetupError(f"{target} appeared meanwhile; left untouched") from None
    fd = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(args) -> None:
    for tool in ("age", "age-plugin-yubikey"):
        if not shutil.which(tool):
            raise SetupError(f"{tool} is not installed; run: brew install age age-plugin-yubikey")
    key = read_private_key()
    address = Account.from_key(key).address
    target = key_path(address)
    print(f"address: {address}")
    if os.path.lexists(target):
        raise SetupError(f"{target} already exists; left untouched")
    if input("Is this your address? Put it behind the YubiKeys? [y/N] ").strip().lower() != "y":
        raise SetupError("cancelled")
    keystore = make_keystore(key)

    idents: list[dict] = []
    for i in range(1, args.yubikeys + 1):
        idents.append(setup_yubikey(i, args.yubikeys, {x["serial"] for x in idents}))

    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkstemp creates a new file (random name, mode 600) exclusively, so cleanup only ever removes our own file
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    staging = Path(name)
    try:
        encrypt_to_staging(keystore, [x["recipient"] for x in idents], fd)
        for ident in idents:
            verify_alone(staging, keystore, ident)
        publish(staging, target)
    finally:
        staging.unlink(missing_ok=True)

    print(f"\ndone: {target}, opened by YubiKey {' or '.join(str(x['serial']) for x in idents)}"
          " with a touch, then the keystore password")
    print("check it: uv run scripts/example_sign.py")
    print("then clear the private key from your clipboard (and clipboard history, if you keep one)")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--yubikeys", type=int, default=2, help="how many YubiKeys can open it (default 2)")
    args = p.parse_args()
    if args.yubikeys < 1:
        p.error("--yubikeys must be at least 1")
    if args.yubikeys == 1:
        print("warning: with one YubiKey there is no backup YubiKey; if it is lost, this key file is unusable")
    try:
        run(args)
    except (SetupError, LoadError) as e:
        sys.exit(f"setup stopped: {e}")
    except (KeyboardInterrupt, EOFError):  # Ctrl-C, or Ctrl-D at a prompt
        sys.exit("\nsetup cancelled")


if __name__ == "__main__":
    main()
