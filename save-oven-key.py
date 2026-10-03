"""Save one selected owner PSK, never the IoTivity storage key."""
import argparse
import base64
import json
import os
from pathlib import Path
import uuid

from inspect_encrypted_store import (
    connection_arguments, credential_section, read_store, selftest,
)


def select_credential(store, target, digest):
    target = uuid.UUID(str(target))
    creds = credential_section(store)
    matches = [c for c in creds["creds"] if c.get("credtype") == 1
               and uuid.UUID(c["subjectuuid"]) == target]
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one PSK for the selected device")
    private = matches[0]["privatedata"]
    if private["encoding"] != "oic.sec.encoding.base64":
        raise RuntimeError("Unexpected key encoding")
    key = base64.b64decode(private["data"], validate=True)
    identity = uuid.UUID(creds["rowneruuid"])
    if len(key) not in (16, 32) or identity.int == 0:
        raise RuntimeError("Unexpected PSK size or missing owner identity")
    return {
        "device_id": str(target),
        "psk_identity": str(identity),
        "psk_hex": key.hex(),
        "source_ciphertext_sha256": digest,
        "validation": "recovered; network authentication pending",
        "identity_contains_nul": b"\0" in identity.bytes,
    }


def save_record(output, record):
    # O_EXCL also rejects an existing symlink. No existing credential is replaced.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    if json.loads(output.read_text()) != record:
        raise RuntimeError("Saved credential did not match")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    connection_arguments(parser)
    parser.add_argument("--device-uuid", required=True, type=uuid.UUID, help="Target appliance OCF UUID, not the owner UUID")
    parser.add_argument("--output", required=True, type=Path, help="New private JSON path; existing files are never replaced")
    args = parser.parse_args()
    if os.path.lexists(args.output):
        parser.error("Output already exists; select a new private path")
    selftest()
    store, digest = read_store(args.serial, str(args.store), args.frida)
    record = select_credential(store, args.device_uuid, digest)
    save_record(args.output, record)
    print("Saved and verified one credential with private file permissions.")
    print("Identity contains a zero byte:", record["identity_contains_nul"])
    print("Network authentication has not been tested by this helper.")


if __name__ == "__main__":
    main()
