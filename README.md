# yubi-deployers

Deploy with an Ethereum key that opens only with a **YubiKey touch** and then the **keystore password**
(scrypt, about 5 seconds). No YubiKey PIN when deploying.

The key is one file, `~/.config/eth/<address>.json.age`: a standard eth keystore (the password layer), encrypted with
[age](https://github.com/FiloSottile/age) to your YubiKeys through
[age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) (touch Always, PIN Never). Either YubiKey opens it,
so the second one is the backup. The file is useless without a YubiKey and the password.

## Prepare each YubiKey (once)

1. PIV (the smart-card application) must be on over USB: Yubico Authenticator, Toggle applications, tick PIV under
   USB, Save; or `ykman config usb --enable PIV`. A YubiKey left FIDO-only shows as "YubiKey FIDO" and
   age-plugin-yubikey keeps saying "Please insert the YubiKey".
2. Firmware 5.7 and later ship an AES PIV management key, which age-plugin-yubikey 0.5.1 cannot use. Switch it to a
   PIN-protected Triple-DES key: `ykman piv access change-management-key -a TDES --protect` (press Enter for the
   default current key, then the PIV PIN; the factory PIN is 123456). Check with `ykman piv info`.
3. Quit Yubico Authenticator while running these scripts: it keeps the smart card busy ("other connections
   outstanding"). If that error stays, GnuPG's card daemon may hold it: `gpgconf --kill scdaemon`.

## Setup (once per key)

```sh
brew install age age-plugin-yubikey
uv run setup_key.py                # paste your deployer private key at the hidden prompt
```

On Linux, install `age` and `age-plugin-yubikey` from your distribution or their releases, and run `pcscd` (the
smart-card service).

1. Paste the private key (64 hex digits, with or without `0x`). Nothing is shown while you paste. Setup prints the
   address so you can check it is the right key.
2. Choose a keystore password and type it twice. This is the password you type on every deploy.
3. Plug in each YubiKey in turn. Each one gets an age identity with touch Always and PIN Never in a free slot, or
   reuses one it already has. Creating an identity asks for the YubiKey's PIV PIN once, during setup only; if the PIN
   is still the factory default, age-plugin-yubikey asks you to change it.
4. The keystore is encrypted to all the YubiKeys, each YubiKey alone must decrypt it back, and only then is the file
   written. It never replaces an existing key file, and the private key itself is never written to disk.

`--yubikeys 3` locks it to three YubiKeys (any one opens it); `--yubikeys 1` is for when only one YubiKey is at hand
(no backup). No wallet yet? Create one with any wallet tool, for example Foundry's `cast wallet new`, and paste its key.

## Check it

```sh
uv run example_sign.py            # touch, password, then it signs a message and a transaction offline
```

Nothing is sent: the transaction is a zero-value transfer to itself on chain id 31337 (a local test chain).

## Use it in a deploy script

Copy `yubi_deployers.py` next to the script (it needs only `eth-account`, plus `age` and `age-plugin-yubikey` on PATH):

```python
from yubi_deployers import load_account

DEPLOYER = "0x..."                 # the address you expect; anything else is refused
acct = load_account(DEPLOYER)      # touch the YubiKey, then type the keystore password
boa.set_network_env(RPC_URL)
boa.env.add_account(acct)
boa.env.eoa = acct.address
```

`load_account` fails, before asking for the password, if age fails or exits early. After the password it fails
if the password is wrong or the file holds a different address. It never writes anything.

## After it works

1. Clear the private key from your clipboard, and from clipboard history if you use a clipboard manager.
2. Back up `~/.config/eth/<address>.json.age` somewhere else (it is safe to copy: it needs a YubiKey and the password).
   Keep the keystore password somewhere separate.
3. Decide whether the raw private key keeps an offline backup: if every YubiKey is lost, the `.age` file cannot be
   opened. Then remove the other copies (environment variables, `.env` files, plain keystores) once your deploy
   scripts use `load_account`.

## What it does not protect against

While a script runs, the key is a normal `eth_account` key in Python memory, so malware already running as you
during a deploy can take it. A YubiKey has no screen to show what is signed. For the most privileged roles a hardware
wallet with a screen, or a multisig, is the stronger fix.

## Tests

```sh
uv run pytest -q
```

They use stand-in `age` and `age-plugin-yubikey` scripts (`tests/conftest.py`), so they need no YubiKey.
