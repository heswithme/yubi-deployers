import getpass
import json
import stat
import sys
import warnings

import pytest
from eth_account import Account

import example_sign
import setup_key
import yubi_deployers
from setup_key import SetupError
from yubi_deployers import LoadError, load_account

PASSWORD = "correct horse"
GOOD = {"slot": 1, "pin": "Never", "touch": "Always"}


def make_keystore(password=PASSWORD):
    acct = Account.create()
    keystore = Account.encrypt(acct.key, password, kdf="scrypt", iterations=2**4)  # tiny cost: tests only
    return acct, json.dumps(keystore).encode()


def write_key_file(acct_address, keystore, recipients):
    path = yubi_deployers.key_path(acct_address)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(("FAKEAGE " + ",".join(recipients) + "\n").encode() + keystore)
    return path


def answer_password(monkeypatch, *answers):
    asked = []
    it = iter(answers)

    def fake(prompt=""):
        asked.append(prompt)
        return next(it)
    monkeypatch.setattr(getpass, "getpass", fake)
    return asked


@pytest.fixture
def one_key_file(yubikeys):
    """A key file for a fresh account, encrypted to YubiKey 111 (plugged in)."""
    yubikeys.add(111, {**GOOD, "tag": "AAA"})
    yubikeys.plug(111)
    acct, keystore = make_keystore()
    write_key_file(acct.address, keystore, ["age1yubikey1aaa"])
    return acct


# ---- loader ----

def test_load_returns_the_expected_account(one_key_file, monkeypatch):
    asked = answer_password(monkeypatch, PASSWORD)
    acct = load_account(one_key_file.address.lower())  # any case of the address works
    assert acct.address == one_key_file.address
    assert acct.key == one_key_file.key
    assert len(asked) == 1


def test_age_failure_with_partial_output_is_refused_before_the_password(one_key_file, monkeypatch):
    monkeypatch.setenv("FAKE_AGE_PARTIAL", "1")  # age writes half of the keystore, then exits 1
    asked = answer_password(monkeypatch, PASSWORD)
    with pytest.raises(LoadError, match="could not decrypt"):
        load_account(one_key_file.address)
    assert asked == []


def test_wrong_password_is_refused(one_key_file, monkeypatch):
    answer_password(monkeypatch, "wrong")
    with pytest.raises(LoadError, match="wrong keystore password"):
        load_account(one_key_file.address)


def test_file_holding_another_address_is_refused(yubikeys, monkeypatch):
    yubikeys.add(111, {**GOOD, "tag": "AAA"})
    yubikeys.plug(111)
    expected = Account.create()
    _, other_keystore = make_keystore()
    write_key_file(expected.address, other_keystore, ["age1yubikey1aaa"])
    answer_password(monkeypatch, PASSWORD)
    with pytest.raises(LoadError, match="not " + expected.address):
        load_account(expected.address)


def test_no_yubikey_plugged_in(one_key_file, yubikeys, monkeypatch):
    yubikeys.plug()
    asked = answer_password(monkeypatch, PASSWORD)
    with pytest.raises(LoadError, match="no YubiKey"):
        load_account(one_key_file.address)
    assert asked == []


def test_yubikey_the_file_is_not_encrypted_to(one_key_file, yubikeys, monkeypatch):
    yubikeys.add(222, {**GOOD, "tag": "BBB"})
    yubikeys.plug(222)
    asked = answer_password(monkeypatch, PASSWORD)
    with pytest.raises(LoadError, match="could not decrypt"):
        load_account(one_key_file.address)
    assert asked == []


def test_missing_key_file(yubikeys):
    with pytest.raises(LoadError, match="no key file"):
        load_account(Account.create().address)


def test_malformed_address_fails_before_anything_runs(yubikeys):
    with pytest.raises(ValueError):
        load_account("0x1234")
    assert yubikeys.calls == []


def test_password_prompt_that_would_echo_is_fatal(one_key_file, monkeypatch):
    def echoing_getpass(prompt=""):
        warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
        return PASSWORD
    monkeypatch.setattr(getpass, "getpass", echoing_getpass)
    with pytest.raises(getpass.GetPassWarning):
        load_account(one_key_file.address)


def test_example_signs_offline(one_key_file, monkeypatch, capsys):
    answer_password(monkeypatch, PASSWORD)
    monkeypatch.setattr(sys, "argv", ["example_sign.py"])  # address picked from the only key file
    example_sign.main()
    out = capsys.readouterr().out
    assert f"loaded {one_key_file.address}" in out
    assert "nothing was sent" in out


# ---- setup ----

UPSTREAM_SAMPLE = """\
#       Serial: 15000001, Slot: 1
#         Name: eth deployer
#      Created: Thu, 12 Nov 2026 21:00:00 +0000
#   PIN policy: Never  (A PIN is NOT required to decrypt)
# Touch policy: Always (A physical touch is required for every decryption)
#    Recipient: age1yubikey1qwerty
AGE-PLUGIN-YUBIKEY-1QWERTY

#       Serial: 15000001, Slot: 2
#         Name: other
#      Created: Thu, 12 Nov 2026 21:00:00 +0000
#   PIN policy: Once   (A PIN is required once per session, if set)
# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)
# Legacy recipient: age1yubikey1legacy
#    Recipient: age1yubikey1asdf
AGE-PLUGIN-YUBIKEY-1ASDF
"""


def test_parse_identities_reads_the_upstream_format():
    ids = setup_key.parse_identities(UPSTREAM_SAMPLE)
    assert ids == [
        {"serial": 15000001, "slot": 1, "pin": "Never", "touch": "Always", "recipient": "age1yubikey1qwerty",
         "stub": "AGE-PLUGIN-YUBIKEY-1QWERTY"},
        {"serial": 15000001, "slot": 2, "pin": "Once", "touch": "Cached", "recipient": "age1yubikey1asdf",
         "stub": "AGE-PLUGIN-YUBIKEY-1ASDF"},
    ]


PASTED = Account.create()  # the key a team member pastes into setup
KEY_HEX = PASTED.key.hex().removeprefix("0x")
SECP256K1_ORDER = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"


def run_setup(monkeypatch, yubikeys, prompts, *argv, secrets=(KEY_HEX, PASSWORD, PASSWORD)):
    """prompts: for each input() prompt in order, the serials plugged in when it is answered (or 'y'/'n').
    secrets: the hidden answers in order (private key, password, password again). Returns the hidden prompts asked."""
    answers = iter(prompts)

    def fake_input(prompt=""):
        a = next(answers)
        if isinstance(a, str):
            return a
        yubikeys.plug(*a)
        return ""
    monkeypatch.setattr("builtins.input", fake_input)
    asked = answer_password(monkeypatch, *secrets)
    monkeypatch.setattr(setup_key, "SCRYPT_N", 2**4)
    monkeypatch.setattr(setup_key, "PLUG_WAIT", 0)
    monkeypatch.setattr(sys, "argv", ["setup_key.py", *argv])
    setup_key.main()
    return asked


def staging_files():
    return [p for p in yubi_deployers.KEY_DIR.glob(".*")] if yubi_deployers.KEY_DIR.exists() else []


def key_dir_entries():
    return list(yubi_deployers.KEY_DIR.iterdir()) if yubi_deployers.KEY_DIR.exists() else []


def test_setup_with_two_yubikeys(yubikeys, monkeypatch, capfd):
    run_setup(monkeypatch, yubikeys, ["y", [111], [222], [111], [222]])
    path = yubi_deployers.key_path(PASTED.address)
    assert key_dir_entries() == [path] and staging_files() == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    for ident in (yubikeys.keys["111"], yubikeys.keys["222"]):  # one new identity on each, right policies
        assert [(i["pin"], i["touch"]) for i in ident] == [("Never", "Always")]
    keystore = json.loads(path.read_bytes().split(b"\n", 1)[1])  # inside age: a standard scrypt keystore
    assert keystore["crypto"]["kdf"] == "scrypt"
    for serial in (111, 222):  # either YubiKey alone opens it, and it is the pasted key
        yubikeys.plug(serial)
        answer_password(monkeypatch, PASSWORD)
        assert load_account(PASTED.address).key == PASTED.key
    out = capfd.readouterr()
    assert KEY_HEX not in (out.out + out.err).lower()  # the key is never printed


@pytest.mark.parametrize("pasted", [
    KEY_HEX,
    "0x" + KEY_HEX,
    "0X" + KEY_HEX.upper(),
    "  0x" + KEY_HEX + " \n",
    "\x1b[200~0x" + KEY_HEX + "\x1b[201~",  # bracketed paste markers
])
def test_setup_accepts_common_paste_forms(yubikeys, monkeypatch, pasted):
    yubikeys.add(111, {**GOOD, "tag": "AAA"})
    run_setup(monkeypatch, yubikeys, ["y", [111], [111]], "--yubikeys", "1", secrets=(pasted, PASSWORD, PASSWORD))
    yubikeys.plug(111)
    answer_password(monkeypatch, PASSWORD)
    assert load_account(PASTED.address).key == PASTED.key


@pytest.mark.parametrize("pasted", [
    "",
    "0x1234",
    KEY_HEX[:-1],
    KEY_HEX + "a",
    KEY_HEX[:-1] + "g",
    KEY_HEX[:32] + " " + KEY_HEX[32:],
    "abandon " * 11 + "about",  # a seed phrase is not accepted
])
def test_setup_rejects_what_is_not_a_private_key(yubikeys, monkeypatch, capfd, pasted):
    with pytest.raises(SystemExit, match="not a private key") as e:
        run_setup(monkeypatch, yubikeys, [], secrets=(pasted,))
    if pasted:  # the error, and anything printed, never repeats what was typed
        assert pasted.strip() not in str(e.value)
        assert pasted.strip() not in capfd.readouterr().out
    assert yubikeys.calls == [] and key_dir_entries() == []


@pytest.mark.parametrize("pasted", ["00" * 32, SECP256K1_ORDER])
def test_setup_rejects_a_key_out_of_range(yubikeys, monkeypatch, capfd, pasted):
    with pytest.raises(SystemExit, match="out of range") as e:
        run_setup(monkeypatch, yubikeys, [], secrets=(pasted,))
    shown = str(e.value) + capfd.readouterr().out
    assert pasted not in shown and (pasted == "00" * 32 or str(int(pasted, 16)) not in shown)
    assert e.value.__context__.__suppress_context__  # the library error (which names the number) is not chained
    assert yubikeys.calls == []


@pytest.mark.parametrize("pasted", ["00" * 31 + "01", f"{int(SECP256K1_ORDER, 16) - 1:064x}"])
def test_setup_accepts_the_smallest_and_largest_keys(yubikeys, monkeypatch, pasted):
    yubikeys.add(111, {**GOOD, "tag": "AAA"})  # leading zeroes are kept: key 1 is 31 zero bytes, then 0x01
    run_setup(monkeypatch, yubikeys, ["y", [111], [111]], "--yubikeys", "1", secrets=(pasted, PASSWORD, PASSWORD))
    address = Account.from_key(bytes.fromhex(pasted)).address
    yubikeys.plug(111)
    answer_password(monkeypatch, PASSWORD)
    assert load_account(address).key == bytes.fromhex(pasted)


def test_ctrl_d_at_the_key_prompt_cancels(yubikeys, monkeypatch):
    def eof(prompt=""):
        raise EOFError
    monkeypatch.setattr(getpass, "getpass", eof)
    monkeypatch.setattr(sys, "argv", ["setup_key.py"])
    with pytest.raises(SystemExit, match="setup cancelled"):
        setup_key.main()
    assert yubikeys.calls == []


def test_private_key_prompt_that_would_echo_is_fatal(yubikeys, monkeypatch):
    def echoing_getpass(prompt=""):
        warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
        return KEY_HEX
    monkeypatch.setattr(getpass, "getpass", echoing_getpass)
    monkeypatch.setattr(sys, "argv", ["setup_key.py"])
    with pytest.raises(getpass.GetPassWarning):
        setup_key.main()
    assert yubikeys.calls == []


def test_setup_reuses_an_existing_touch_only_identity(yubikeys, monkeypatch):
    yubikeys.add(111, {**GOOD, "tag": "AAA"})
    run_setup(monkeypatch, yubikeys, ["y", [111], [111]], "--yubikeys", "1")
    assert yubikeys.keys["111"] == [{**GOOD, "tag": "AAA"}]
    assert not any("--generate" in c for c in yubikeys.calls)
    assert key_dir_entries() == [yubi_deployers.key_path(PASTED.address)]


def test_setup_does_not_reuse_an_identity_with_a_pin(yubikeys, monkeypatch):
    yubikeys.add(111, {"slot": 1, "pin": "Once", "touch": "Always", "tag": "AAA"})
    run_setup(monkeypatch, yubikeys, ["y", [111], [111]], "--yubikeys", "1")
    assert [(i["pin"], i["touch"]) for i in yubikeys.keys["111"]] == [("Once", "Always"), ("Never", "Always")]


def test_setup_refuses_the_same_yubikey_twice(yubikeys, monkeypatch):
    with pytest.raises(SystemExit, match="already set up as an earlier one"):
        run_setup(monkeypatch, yubikeys, ["y", [111], [111]])
    assert key_dir_entries() == []


def test_setup_refuses_two_yubikeys_plugged_in_at_once(yubikeys, monkeypatch):
    with pytest.raises(SystemExit, match="age-plugin-yubikey --generate"):
        run_setup(monkeypatch, yubikeys, ["y", [111, 222]])


def test_setup_stops_when_a_yubikey_cannot_decrypt_alone(yubikeys, monkeypatch):
    # YubiKey 222 is unplugged when its own check comes: nothing is published, the staging file is removed
    with pytest.raises(SystemExit, match="222 slot 1 is not plugged in"):
        run_setup(monkeypatch, yubikeys, ["y", [111], [222], [111], [111]])
    assert key_dir_entries() == []


def test_setup_cancelled_at_the_address_prompt_asks_no_password(yubikeys, monkeypatch):
    with pytest.raises(SystemExit, match="cancelled"):  # only the key is supplied: a password prompt would fail
        run_setup(monkeypatch, yubikeys, ["n"], secrets=(KEY_HEX,))
    assert yubikeys.calls == [] and key_dir_entries() == []


def test_setup_rejects_mismatched_passwords(yubikeys, monkeypatch):
    with pytest.raises(SystemExit, match="passwords differ"):
        run_setup(monkeypatch, yubikeys, ["y"], secrets=(KEY_HEX, "a", "b"))
    assert yubikeys.calls == []


def test_setup_rejects_an_empty_password(yubikeys, monkeypatch):
    with pytest.raises(SystemExit, match="empty password"):
        run_setup(monkeypatch, yubikeys, ["y"], secrets=(KEY_HEX, ""))
    assert yubikeys.calls == []


def test_setup_refuses_an_existing_key_file_before_any_password(yubikeys, monkeypatch):
    existing = write_key_file(PASTED.address, b"old", ["age1yubikey1zzz"])
    with pytest.raises(SystemExit, match="already exists"):  # only the key is supplied
        run_setup(monkeypatch, yubikeys, [], secrets=(KEY_HEX,))
    assert existing.read_bytes().endswith(b"old")
    assert yubikeys.calls == []


def test_publish_never_replaces_an_existing_key_file(tmp_path):
    staging, target = tmp_path / ".staging", tmp_path / "target"
    staging.write_bytes(b"new")
    target.write_bytes(b"old")
    with pytest.raises(SetupError, match="left untouched"):
        setup_key.publish(staging, target)
    assert target.read_bytes() == b"old"


def test_failed_setup_removes_only_its_own_staging_file(yubikeys, monkeypatch):
    # a leftover from an older run must survive; only the file this run created is removed
    yubi_deployers.KEY_DIR.mkdir(parents=True)
    stray = yubi_deployers.KEY_DIR / ".0xABC.json.age.123.tmp"
    stray.write_bytes(b"leftover")
    with pytest.raises(SystemExit, match="222 slot 1 is not plugged in"):
        run_setup(monkeypatch, yubikeys, ["y", [111], [222], [111], [111]])
    assert key_dir_entries() == [stray]
    assert stray.read_bytes() == b"leftover"


def test_setup_with_three_yubikeys(yubikeys, monkeypatch):
    yubikeys.add(333)
    run_setup(monkeypatch, yubikeys, ["y", [111], [222], [333], [111], [222], [333]], "--yubikeys", "3")
    for serial in (111, 222, 333):  # each of the three opens it alone
        yubikeys.plug(serial)
        answer_password(monkeypatch, PASSWORD)
        assert load_account(PASTED.address).key == PASTED.key
