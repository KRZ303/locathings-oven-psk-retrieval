"""Read an existing SmartThings store; verify its ciphertext MAC before decoding."""
import argparse
import base64
import hashlib
import hmac
import io
import pathlib
import re
import shlex
import subprocess
import uuid

import cbor2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE = "com.samsung.android.oneconnect"


def decrypt(key, data):
    # Layout verified against psiDecrypt in this app's ARM64 liboctbstack.so.
    if len(key) != 32 or len(data) < 64 or len(data) % 16:
        raise ValueError("Invalid encrypted store size")
    iv, ciphertext, mac = data[:16], data[16:-32], data[-32:]
    if not hmac.compare_digest(hmac.digest(key, ciphertext, "sha256"), mac):
        raise ValueError("Encrypted store authentication failed")
    decoder = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decoder.update(ciphertext) + decoder.finalize()
    size = len(data) - 64 + (iv[15] & 15)
    return padded[:size]


def selftest():
    key = bytes(range(32))
    for size in (1, 15, 16, 17, 32, 129):
        plain = b"x" * size
        iv = bytes(15) + bytes([size & 15])
        padded = plain + bytes(16 - size % 16)
        encoder = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encoder.update(padded) + encoder.finalize()
        data = iv + ciphertext + hmac.digest(key, ciphertext, "sha256")
        assert decrypt(key, data) == plain
        try:
            decrypt(key, data[:-1] + bytes([data[-1] ^ 1]))
        except ValueError:
            pass
        else:
            raise AssertionError("Corrupted authentication tag was accepted")


def decode_cbor(data):
    stream = io.BytesIO(data)
    result = cbor2.CBORDecoder(stream).decode()
    if stream.read():
        raise ValueError("Unexpected trailing CBOR data")
    return result


def credential_section(store):
    value = store["cred"]
    return decode_cbor(value) if isinstance(value, bytes) else value


def read_store(serial, store_id, frida="frida"):
    # A canonical UUID prevents paths or shell syntax entering the root command.
    store_id = str(uuid.UUID(store_id))

    def adb(*args):
        return subprocess.check_output(
            ["adb", "-s", serial, *args], stderr=subprocess.PIPE, timeout=15
        )

    def root(command):
        return adb("exec-out", shlex.join(["su", "-c", command]))

    package_info = adb("shell", "dumpsys", "package", PACKAGE).decode()
    if not re.search(r"\bversionName=1\.8\.51\.30\s", package_info) or not re.search(
        r"\bversionCode=185130010\b", package_info
    ):
        raise RuntimeError("Unsupported SmartThings build; do not bypass this check")
    if adb("shell", "getprop", "ro.product.cpu.abi").strip() != b"arm64-v8a":
        raise RuntimeError("Only the tested ARM64 build is supported")
    pid = int(adb("shell", "pidof", PACKAGE).strip())
    status = root(f"cat /proc/{pid}/status").decode()
    uid = int(re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE).group(1))
    frozen = root(f"cat /sys/fs/cgroup/apps/uid_{uid}/pid_{pid}/cgroup.freeze").strip()
    if frozen != b"0":
        raise RuntimeError("SmartThings is frozen; open the app first")
    port = adb("forward", "tcp:0", "tcp:27042").decode().strip()
    try:
        result = subprocess.run([
            frida, "-H", "127.0.0.1:" + port,
            "-p", str(pid), "-q", "-t", "3", "-l", str(ROOT / "read-storage-key.js"),
        ], capture_output=True, text=True, timeout=40)
        lines = result.stdout.splitlines()
        keys = [line.removeprefix("RECOVERY_KEY:") for line in lines if line.startswith("RECOVERY_KEY:")]
        if result.returncode or len(keys) != 1:
            raise RuntimeError("Could not read the existing storage key; raw output suppressed")
        key = base64.b64decode(keys[0], validate=True)
    finally:
        adb("forward", "--remove", "tcp:" + port)
    data = root(f"cat /data/user/0/{PACKAGE}/files/{store_id}.datenc")
    plain = decrypt(key, data)
    store = decode_cbor(plain)
    return store, hashlib.sha256(data).hexdigest()


def connection_arguments(parser):
    parser.add_argument("--serial", required=True, help="ADB serial of your rooted phone")
    parser.add_argument("--store", required=True, type=uuid.UUID, help="Account store UUID, without .datenc")
    parser.add_argument("--frida", default="frida", help="Frida CLI executable from the prepared environment")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    connection_arguments(parser)
    parser.add_argument("--show-identifiers", action="store_true", help="Print private owner and PSK subject UUIDs, never keys")
    args = parser.parse_args()
    selftest()
    store, _ = read_store(args.serial, str(args.store), args.frida)
    creds = credential_section(store)
    entries = creds.get("creds", [])
    print("PASS: ciphertext MAC and complete CBOR decoding verified")
    print("Credential count:", len(entries))
    print("PSK count:", sum(c.get("credtype") == 1 for c in entries))
    if args.show_identifiers:
        print("Credential owner:", str(uuid.UUID(creds["rowneruuid"])))
        for cred in entries:
            if cred.get("credtype") == 1:
                print("PSK subject:", str(uuid.UUID(cred["subjectuuid"])))


if __name__ == "__main__":
    main()
