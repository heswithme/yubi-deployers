"""Load the deployer with a YubiKey touch and the keystore password, then sign offline. Nothing is sent.

    uv run scripts/example_sign.py [ADDRESS]     # ADDRESS defaults to the only key file in ~/.config/eth

A deploy script does the same load, then hands the account to titanoboa:
    acct = load_account(DEPLOYER)
    boa.set_network_env(RPC_URL)
    boa.env.add_account(acct)
    boa.env.eoa = acct.address
"""
import sys

from eth_account import Account
from eth_account.messages import encode_defunct

import yubi_deployers
from yubi_deployers import LoadError, load_account


def only_address() -> str:
    files = sorted(yubi_deployers.KEY_DIR.glob("0x*.json.age"))
    if len(files) != 1:
        sys.exit(f"{len(files)} key files in {yubi_deployers.KEY_DIR};"
                 " pass the address: uv run scripts/example_sign.py 0x...")
    return files[0].name.removesuffix(".json.age")


def main() -> None:
    address = sys.argv[1] if len(sys.argv) > 1 else only_address()
    try:
        acct = load_account(address)
    except LoadError as e:
        sys.exit(f"not loaded: {e}")
    print(f"loaded {acct.address}")

    message = encode_defunct(text="yubi-deployers example")
    signature = acct.sign_message(message).signature
    if Account.recover_message(message, signature=signature) != acct.address:
        sys.exit("message signature does not recover the address")
    print(f"signed a message, signature 0x{signature.hex()[:16]}...")

    # A zero-value transfer to itself on a local test chain id (31337), never broadcast.
    tx = {"type": 2, "chainId": 31337, "nonce": 0, "to": acct.address, "value": 0, "data": b"",
          "gas": 21_000, "maxFeePerGas": 10**9, "maxPriorityFeePerGas": 10**9}
    signed = acct.sign_transaction(tx)
    if Account.recover_transaction(signed.raw_transaction) != acct.address:
        sys.exit("transaction signature does not recover the address")
    print(f"signed a transaction, hash 0x{signed.hash.hex()}")
    print("both signatures recover the address; nothing was sent")


if __name__ == "__main__":
    main()
