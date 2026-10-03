# Samsung oven PSK recovery with rooted Android 17

This repository documents one successful Samsung oven recovery on 2026-10-03.
It contains sanitized versions of the helpers used during that recovery.

The oven rejected LocalThings' certificate authentication. We recovered its existing owner pre-shared key (PSK) from SmartThings on a rooted Android phone.
An authenticated local read then succeeded through Mbed TLS. After a separate transport patch and Home Assistant restart, the owner confirmed the oven connected.

**The key came from an account-specific encrypted `.datenc` file, not the main Core credential file.**
The phone had to complete SmartThings registration before the matching credential appeared in the store we recovered.

This is a version-specific research method, not a universal Samsung extractor or an official Samsung tool.
The oven's retail model number was not established. Its reported board prefix was `LCD_R18_SCO_QMD_EU_22K`, with SmartThings profile `DA-KS-OVEN-0105X`.

## Tested environment

- Phone: Motorola Edge 30 Fusion, ARM64, rooted with KernelSU.
- Android: 17.
- SmartThings: `1.8.51.30`, version code `185130010`.
- Android package: `com.samsung.android.oneconnect`, primary Android user `0`.
- Host: macOS, ADB, Python 3.14.5.
- Frida host and Android server: `17.21.0`; `frida-tools`: `14.10.4`.
- Store decoding: `cbor2==6.1.5`, `cryptography==50.0.2`.
- Initial Home Assistant integration: LocalThings `0.31.0`.
- Successful standalone DTLS test: Mbed TLS `3.6.7`.

The Java class names are obfuscated and specific to this SmartThings build.
Both the host helper and Java agent reject other app builds or architectures.
Matching version numbers are necessary, but they do not establish compatibility with every APK variant.
Other Android versions, work profiles, and filesystem layouts have not been validated.

## Recovery sequence

1. A washer worked with certificate authentication, but the oven returned `unknown_ca`.
2. The oven's unencrypted `/oic/sec/doxm` response advertised PSK security through `sct=1`.
3. The available phone could use the cloud tile, but another phone had performed the original pairing.
4. The main Core store, `oic_svr_db_client.dat`, and its live native credential list contained ten certificates and no PSK.
5. The owner removed the oven and completed registration again through SmartThings on the rooted phone.
6. Core still showed no PSK. An account-specific `.datenc` file held the relevant credential; its plaintext `.dat` companion contained baseline certificates.
7. The app's existing CryptoManager unwrapped its existing IoTivity storage key. The host verified the ciphertext MAC and decoded the encrypted store.
8. Exactly one type-1 credential matched the oven's device UUID. Its base64 value decoded to a 16-byte PSK.
9. The credential resource's owner UUID matched the oven's separately reported `devowneruuid`.
10. A separate Mbed TLS test authenticated and read `/oic/d`, matching the expected oven identity.
11. Local transport and integration patches enabled the same identity in Home Assistant. The owner imported the owner PSK and confirmed connection.

## Boundaries and risks

Use this method only with a phone, account, and appliance you own or are authorized to inspect.

**Removing an appliance can reset its network setup and break routines or scene references.**
Save the relevant registration and automation details privately before considering removal.
Those records are not a tested restore procedure.
Inspect existing account stores before deciding that re-registration is necessary.
Do not clear SmartThings data, uninstall the app, or delete its keys.

The extraction helpers do not pair devices, generate keys, initialize OCF, or write appliance security resources.
SmartThings performs its own registration flow; its internal security changes were not independently audited.
The helpers attach to a running app, which can still disrupt that app if instrumentation fails.

**The output JSON contains a usable secret. File mode `0600` does not encrypt it.**
Keep it on a trusted, encrypted host and outside shared folders.
The ignored `private/` directory helps prevent accidental Git additions; it is not a security boundary.
Do not publish raw Frida output, decrypted CBOR, app databases, screenshots, or generated credentials.
Keep error tracebacks private: ADB failures can include the phone serial and the selected store path.
Do not run `read-storage-key.js` directly in a logged terminal: its `RECOVERY_KEY` message contains the storage key.
The Python helper captures that message without printing or deliberately saving it.
Python, Frida, swap, and crash dumps can retain memory; this is not a secure-memory implementation.

## Prepare the tools

The following commands target the tested macOS/Linux-style environment.
The sanitized helpers passed offline tests, but were not rerun against the phone after publication cleanup.
The successful live recovery used their original, device-specific versions.

1. Install ADB from the official [Android Platform-Tools distribution](https://developer.android.com/tools/releases/platform-tools).
2. Clone this repository.
3. Create the Python environment from the repository directory.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m unittest -v test_recovery.py
```

4. Download `frida-server-17.21.0-android-arm64.xz` from the [official Frida release](https://github.com/frida/frida/releases/tag/17.21.0).
5. Verify the download against the release asset's SHA-256 digest.
6. Decompress the server into the ignored private directory.

```sh
mkdir -m 700 private
xz -dc /path/to/frida-server-17.21.0-android-arm64.xz > private/frida-server
```

7. Unlock the phone and authorize USB debugging.
8. Grant the ADB shell root access in your root manager.
9. Select your phone's serial from `adb devices -l`.

```sh
adb devices -l
export ANDROID_SERIAL='YOUR_ADB_SERIAL'
adb -s "$ANDROID_SERIAL" shell su -c id
adb -s "$ANDROID_SERIAL" shell dumpsys package com.samsung.android.oneconnect
```

The root check must report `uid=0`. The package output must match the tested version name and code.
Do not bypass the version checks for a newer build without inspecting that build's implementation.

10. Open SmartThings and keep it foreground with the screen unlocked.
11. Copy the verified server to a new, task-specific phone path.

```sh
adb -s "$ANDROID_SERIAL" push private/frida-server /data/local/tmp/psk-recovery-frida-server
adb -s "$ANDROID_SERIAL" shell chmod 700 /data/local/tmp/psk-recovery-frida-server
```

12. Start the server in a separate terminal and leave that terminal open.

```sh
adb -s "$ANDROID_SERIAL" shell 'su -c "/data/local/tmp/psk-recovery-frida-server -l 127.0.0.1:27042"'
```

The server listens only on the phone's loopback interface.
The host helper creates one temporary ADB forward and removes it after the Frida call, including on ordinary failures.
It does not remove unrelated forwards or stop other instrumentation sessions.

## Find the correct store

The relevant files in this case were:

```text
/data/user/0/com.samsung.android.oneconnect/
  shared_prefs/iotivityKey.xml
  files/<ACCOUNT_STORE_UUID>.datenc   encrypted credential store
  files/<ACCOUNT_STORE_UUID>.dat      certificate-only baseline in this case
  files/<ACCOUNT_STORE_UUID>.db       companion provisioning database
```

The account store UUID is not the oven UUID or the PSK identity.
List candidate filenames without exporting their contents:

```sh
adb -s "$ANDROID_SERIAL" shell 'su -c "find /data/user/0/com.samsung.android.oneconnect/files -maxdepth 1 -type f -name \*.datenc"'
```

Set the UUID from the intended filename, without its extension:

```sh
export STORE_UUID='YOUR_ACCOUNT_STORE_UUID'
python inspect_encrypted_store.py --serial "$ANDROID_SERIAL" --store "$STORE_UUID"
```

The default output reports credential counts, not keys or identifiers.
If several stores exist, inspect their counts individually.
Do not delete a store because it appears stale.

To identify candidate PSK subjects, explicitly request identifier output:

```sh
python inspect_encrypted_store.py --serial "$ANDROID_SERIAL" --store "$STORE_UUID" --show-identifiers
```

Keep this output private. Match the selected subject UUID to the intended appliance's OCF device UUID.
Read-only `/oic/d` or `/oic/sec/doxm` discovery can supply that UUID; this repository does not include a discovery client.
The companion database's `T_DEVICE_LIST.UUID` and `otm.uuid` also matched the oven during the investigation.
The observed `otm.state` was `2`; this is evidence from this app, not a universal pairing-state contract.

The cloud device ID happened to match the OCF device UUID in this case. Do not assume they always match.
An unauthenticated discovery reply is a cross-check, not proof of authenticated device identity.

### If the key is absent

Do not conclude that no PSK exists from Core's `oic_svr_db_client.dat` alone.
Check account-specific `.datenc` stores first.
If the original pairing phone is available, inspect its intact SmartThings installation before disrupting registration.

If re-registration is necessary, confirm the risk and preserve the current account details first.
Use SmartThings' normal remove/add flow for only the intended appliance.
Keep using the prepared rooted phone and the same SmartThings installation.
Follow the oven's panel prompts and [Samsung's connection instructions](https://www.samsung.com/uk/support/home-appliances/how-to-connect-to-smartthings-on-my-oven/).
After SmartThings reports a working registration, repeat the account-store inspection.

## Save the selected PSK

Set the appliance's verified OCF UUID, not the credential owner UUID:

```sh
export OVEN_UUID='YOUR_OVEN_OCF_DEVICE_UUID'
python save-oven-key.py \
  --serial "$ANDROID_SERIAL" \
  --store "$STORE_UUID" \
  --device-uuid "$OVEN_UUID" \
  --output private/owner-psk.json
```

The helper requires exactly one matching `credtype=1` entry.
It accepts only the observed base64 encoding and a 16-byte or 32-byte key.
The live case used a 16-byte key; 32-byte acceptance is an offline-tested allowance, not another verified appliance result.
It creates a new file with mode `0600`, refuses existing paths, and verifies the saved JSON.

The file contains:

- `device_id`: the selected appliance UUID from the credential's `subjectuuid`.
- `psk_identity`: the credential resource's `rowneruuid`, used as the owner identity.
- `psk_hex`: the decoded PSK in hexadecimal.
- `identity_contains_nul`: whether the identity's 16 raw bytes contain a zero byte.
- `source_ciphertext_sha256`: a private provenance checksum.
- `validation`: a reminder that extraction does not establish network authentication.

The store's own `doxm.devowneruuid` was zero in this case. It is not the source of the extracted PSK identity.
The comparison used the oven's separate, live `/oic/sec/doxm` response.

Open the saved JSON privately and import `psk_identity` and `psk_hex` using LocalThings' **owner PSK** option.
Use the appliance's current LAN address in the IP field.
Do not paste the IoTivity storage key, account store UUID, or oven UUID into the owner identity field.

## Why extraction alone did not finish this oven

Our owner UUID contained a NUL byte in its binary representation.
The original transport rejected it with:

```text
identity cannot contain a NUL byte
```

The relevant OpenSSL DTLS 1.2 PSK callback takes a NUL-terminated C string for the identity.
This OCF identity requires all 16 raw UUID bytes, including zero bytes.
Removing the guard, removing zeros, or sending the textual UUID does not solve that mismatch.

Mbed TLS accepts the identity as bytes plus an explicit length.
A standalone Mbed TLS 3.6.7 test negotiated `TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256` and authenticated successfully.
Its `GET /oic/d` returned the expected oven identity; `close_notify` completed successfully.
No heating command or security-resource write was part of that test.

The subsequent fix covered two projects:

- [SmartThings-Local](https://github.com/QuiteYellow/SmartThings-Local): the DTLS transport and optional Mbed TLS backend.
- [LocalThings](https://github.com/mbillow/localthings): credential validation and integration messaging.

The local patch selected Mbed TLS only for identities containing zero bytes.
Other PSK identities and certificate sessions retained the OpenSSL path.
The patched session authenticated on macOS and from Home Assistant's Linux runtime before deployment.
After the authorized patch deployment and restart, the existing washer resumed observations.
The owner then confirmed successful oven setup in Home Assistant.
A subsequent read-only HA check found both the oven and washer entries loaded.
The oven currently exposes only a connection-mode sensor, reporting `poll`; diagnostics show no active observations.
This proves authentication and setup, not full oven entity coverage or working heating controls.

**This extraction repository does not contain or install those separate patches.**
The [transport PR](https://github.com/QuiteYellow/SmartThings-Local/pull/115) and [integration PR](https://github.com/mbillow/localthings/pull/575) publish the changes for review.
The optional Mbed TLS native module requires a separate build for the target architecture and C library.
The transport wheel contains its source, not a compiled module; installing the integration change alone does not enable binary identities.
Do not assume an upstream release supports this identity merely because this recovery worked.
Consult [LocalThings issue #435](https://github.com/mbillow/localthings/issues/435) for the upstream discussion.
If your identity contains zero bytes, check transport support before expecting the recovered key to authenticate.

## How the decryption works

The app preference `iotivityKey`, inside `shared_prefs/iotivityKey.xml`, holds an existing `:v1:` wrapped value.
APK inspection mapped `CryptoManager.a(String)` to the string decryption path.
The Frida agent obtains the existing manager through `sk.b.a(context)`, casts to `com.samsung.android.oneconnect.f4`, and calls `X()`.
It requires the existing `manager.b` key to be loaded before invoking that decryption method.
The result is base64 text encoding the 32-byte IoTivity storage key.

This uses the app's existing Android Keystore-backed decryption operation.
It does not export the Keystore wrapping key or generate a replacement storage key.
The investigation deliberately avoided the app's key-generation utility and OCF initialization routines.
The early native crypto test in Core failed because that process had no PSI encryption key initialized.
The successful agent attached to the main app process, not `:Core`.

Native inspection of this build's ARM64 `psiDecrypt` established the following file layout:

```text
16-byte IV | AES-256-CBC ciphertext (whole blocks) | 32-byte HMAC-SHA256

HMAC input       = ciphertext only
AES key          = recovered 32-byte storage key
HMAC key         = the same 32-byte storage key
plaintext length = total file length - 64 + (IV[15] & 0x0f)
```

The decoder checks the ciphertext HMAC before decrypting.
**The observed MAC does not cover the IV.** A valid MAC does not authenticate the complete file or its length metadata.
Use data read from the intended trusted phone, then require valid, complete CBOR and an authenticated appliance identity check.
The length convention is specific to this format; the helper does not apply standard PKCS#7 unpadding.
The credential section can itself be a CBOR byte string inside the outer CBOR map.

## Troubleshooting and cleanup

- **`su: inaccessible or not found`:** authorize the ADB shell in the root manager before continuing.
- **Attach timeout:** unlock the phone, foreground SmartThings, and retry with a fresh PID.
- **Frozen process:** keep the app foreground; do not disable Android's cached-process freezer globally.
- **Unsupported build:** inspect the installed APK before porting the obfuscated Java calls.
- **Missing loaded key:** preserve the app data; confirm normal SmartThings startup and registration before retrying.
- **MAC or CBOR failure:** stop; do not bypass validation or try the result as a credential.
- **Zero or multiple matching PSKs:** verify the store and device UUID; do not select the first arbitrary entry.
- **Existing output file:** keep it; choose a new private filename for a deliberate second recovery.

Stop only the Frida server started for this task after recovery.
Check its exact process and arguments before terminating it.
Remove only its task-specific executable when it is no longer needed.
Check `adb forward --list` for leftovers if the host process was forcibly terminated.
Do not remove unrelated forwards or kill all Frida processes.

## Included files and verification limits

- `read-storage-key.js`: adapted original agent, with build checks and secret-safe error output.
- `inspect_encrypted_store.py`: original decoder with parameterized phone/store selection and dynamic UID discovery.
- `save-oven-key.py`: original selection/save logic, with explicit arguments and exclusive private output creation.
- `test_recovery.py`: synthetic offline checks; no phone or appliance access.
- `requirements.txt`: the recovery environment's dependency versions.
- `.gitignore`: excludes common recovery artifacts and credentials.

The README was reconstructed from the full conversation and checked against the saved research notes and helper sources.
Public examples contain placeholders or synthetic values, not recovered credentials.
The private archive remains separate and unchanged.
It includes material intentionally excluded here: credentials, raw receipts, app databases, APK/native binaries, screenshots, and HA backups.
Failed exploratory agents and deployment-specific scripts are also excluded because they are not needed for this extraction recipe.

The recorded live result covers one oven, one app build, and one phone.
Offline checks cover decoding, malformed input, credential selection, file permissions, and helper cleanup.
They do not establish compatibility with another SmartThings release, another oven, or every appliance control.

For the earlier, separate washer/dryer investigation, see the upstream [credential-acquisition notes](https://github.com/mbillow/localthings/blob/main/docs/credential-acquisition.md).
Those notes inspired the registration-and-recovery approach; their unpublished helper code was not used in this repository.
