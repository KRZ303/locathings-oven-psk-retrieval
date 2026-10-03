"""Offline checks using synthetic credentials only; never contact a device."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import cbor2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac

import inspect_encrypted_store as recovery

spec = importlib.util.spec_from_file_location("save_oven_key", Path(__file__).with_name("save-oven-key.py"))
saver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(saver)

# Deliberately synthetic byte sequences, not appliance or account identifiers.
TARGET = uuid.UUID(bytes=bytes(range(16, 32)))
OWNER = uuid.UUID(bytes=bytes(range(16)))
KEY = bytes(range(32))


def fixture():
    return {"rowneruuid": str(OWNER), "creds": [{
        "subjectuuid": str(TARGET), "credtype": 1,
        "privatedata": {"encoding": "oic.sec.encoding.base64",
                        "data": base64.b64encode(KEY[:16]).decode()},
    }]}


def encrypted(plain):
    iv = bytes(15) + bytes([len(plain) & 15])
    padded = plain + bytes(16 - len(plain) % 16)
    encoder = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    ciphertext = encoder.update(padded) + encoder.finalize()
    return iv + ciphertext + hmac.digest(KEY, ciphertext, "sha256")


class RecoveryTests(unittest.TestCase):
    def test_decoder_roundtrips_and_mac_rejection(self):
        recovery.selftest()
        data = encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())}))
        store = recovery.decode_cbor(recovery.decrypt(KEY, data))
        self.assertEqual(recovery.credential_section(store), fixture())
        with self.assertRaises(ValueError):
            recovery.decrypt(KEY, data[:20] + bytes([data[20] ^ 1]) + data[21:])

    def test_invalid_lengths_and_trailing_cbor(self):
        for key, data in ((KEY[:-1], bytes(64)), (KEY, bytes(63)), (KEY, bytes(65))):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                recovery.decrypt(key, data)
        with self.assertRaises(ValueError):
            recovery.decode_cbor(cbor2.dumps({}) + b"\x00")
        with self.assertRaises(ValueError):
            recovery.credential_section({"cred": cbor2.dumps(fixture()) + b"\x00"})

    def test_owner_identity_and_nul_are_preserved(self):
        record = saver.select_credential({"cred": cbor2.dumps(fixture())}, TARGET, "synthetic")
        self.assertEqual(record["device_id"], str(TARGET))
        self.assertEqual(record["psk_identity"], str(OWNER))
        self.assertEqual(uuid.UUID(record["psk_identity"]).bytes, OWNER.bytes)
        self.assertEqual(record["psk_hex"], KEY[:16].hex())
        self.assertTrue(record["identity_contains_nul"])
        self.assertIn("pending", record["validation"])

    def test_missing_or_ambiguous_match_rejected(self):
        for count in (0, 2):
            creds = fixture()
            creds["creds"] *= count
            with self.subTest(count=count), self.assertRaises(RuntimeError):
                saver.select_credential({"cred": creds}, TARGET, "synthetic")

    def test_wrong_subject_or_type_rejected(self):
        for field, value in (("subjectuuid", str(OWNER)), ("credtype", 8)):
            creds = fixture()
            creds["creds"][0][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                saver.select_credential({"cred": creds}, TARGET, "synthetic")

    def test_private_key_validation(self):
        cases = [("encoding", "raw"), ("data", "not base64!"),
                 ("data", base64.b64encode(b"short").decode())]
        for field, value in cases:
            creds = fixture()
            creds["creds"][0]["privatedata"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises((ValueError, RuntimeError)):
                saver.select_credential({"cred": creds}, TARGET, "synthetic")
        creds = fixture()
        creds["creds"][0]["privatedata"]["data"] = base64.b64encode(KEY).decode()
        self.assertEqual(saver.select_credential({"cred": creds}, TARGET, "synthetic")["psk_hex"], KEY.hex())
        creds["rowneruuid"] = str(uuid.UUID(int=0))
        with self.assertRaises(RuntimeError):
            saver.select_credential({"cred": creds}, TARGET, "synthetic")

    def test_output_private_and_never_overwritten(self):
        record = saver.select_credential({"cred": fixture()}, TARGET, "synthetic")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "synthetic.json"
            saver.save_record(output, record)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(json.loads(output.read_text()), record)
            with self.assertRaises(FileExistsError):
                saver.save_record(output, {})
            link = Path(directory) / "link.json"
            link.symlink_to(output)
            with self.assertRaises(FileExistsError):
                saver.save_record(link, {})
            self.assertEqual(json.loads(output.read_text()), record)

    def test_host_forward_cleanup_and_dynamic_uid(self):
        data = encrypted(cbor2.dumps({"cred": cbor2.dumps(fixture())}))
        prefix = [b"versionName=1.8.51.30\nversionCode=185130010 minSdk=1\n",
                  b"arm64-v8a\n", b"123\n", b"Uid:\t10001\t10001\n", b"0\n", b"45678\n"]
        result = subprocess.CompletedProcess([], 0, "RECOVERY_KEY:" + base64.b64encode(KEY).decode() + "\n", "")
        for failure in (False, True):
            responses = copy.copy(prefix) + [b""] + ([] if failure else [data])
            with self.subTest(failure=failure), patch.object(recovery.subprocess, "check_output", side_effect=responses) as adb:
                with patch.object(recovery.subprocess, "run", side_effect=TimeoutError if failure else None, return_value=result):
                    if failure:
                        with self.assertRaises(TimeoutError):
                            recovery.read_store("synthetic-serial", str(TARGET))
                    else:
                        store, digest = recovery.read_store("synthetic-serial", str(TARGET))
                        self.assertEqual(recovery.credential_section(store), fixture())
                        self.assertEqual(len(digest), 64)
                calls = [call.args[0] for call in adb.call_args_list]
                self.assertTrue(any("uid_10001/pid_123" in call[-1] for call in calls))
                self.assertIn(["adb", "-s", "synthetic-serial", "forward", "--remove", "tcp:45678"], calls)

    def test_wrong_build_rejected_before_attachment(self):
        with patch.object(recovery.subprocess, "check_output", return_value=b"versionName=9.9\n") as adb:
            with patch.object(recovery.subprocess, "run") as frida:
                with self.assertRaises(RuntimeError):
                    recovery.read_store("synthetic-serial", str(TARGET))
                self.assertEqual(adb.call_count, 1)
                frida.assert_not_called()

    def test_invalid_store_cannot_reach_root_shell(self):
        with patch.object(recovery.subprocess, "check_output") as adb:
            with self.assertRaises(ValueError):
                recovery.read_store("synthetic-serial", "../invalid; command")
            adb.assert_not_called()


if __name__ == "__main__":
    unittest.main()
