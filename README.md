# TL-WR1502X v1.0 — Firmware Analysis & Security Research

Analysis of the TP-Link TL-WR1502X v1.0 portable Wi-Fi 6 router (AX1500 class),
firmware version 1.2.11 Build 20251009 rel.56489(4555).

Four confirmed security findings, with reproduction tooling and evidence.

---

## Table of Contents

- [Hardware](#hardware)
- [Firmware Format](#firmware-format)
- [Partition Layout](#partition-layout)
- [Boot Sequence](#boot-sequence)
- [Findings](#findings)
  - [Finding 1 — TDP authentication token from public DEV_ID](#finding-1--tdp-authentication-token-from-public-dev_id)
  - [Finding 2 — Static AES key for stored credentials](#finding-2--static-aes-key-for-stored-credentials)
  - [Finding 3 — Configuration backup decryptable](#finding-3--configuration-backup-decryptable)
  - [Finding 4 — Modified backup accepted without integrity check](#finding-4--modified-backup-accepted-without-integrity-check)
- [Reproduction](#reproduction)
- [Tooling](#tooling)
- [UART Access](#uart-access)
- [Flash Dump](#flash-dump)
- [Mitigations](#mitigations)
- [References](#references)

---

## Hardware

Confirmed via physical teardown and boot log analysis.

| Component | Chip | Notes |
|---|---|---|
| **SoC** | Realtek RTL8197F-VG | MIPS 24Kc, 999 MHz, single core |
| **RAM** | Integrated DDR2 | 128 MB (`0x00000000 - 0x08000000`) |
| **Flash** | ESMT F50L1G41LB | 128 MB SPI NAND, SLC, 2048-byte page, 64-byte OOB, 128 KB erase block |
| **2.4 GHz radio** | Integrated in SoC | `rtl8192cd` driver, RFE type 0 |
| **5 GHz radio** | Realtek RTL8832BR | PCIe device, firmware V0.27.63.2 |
| **Ethernet switch** | Realtek RTL8367D | `rtl865x` driver, 2 ports (eth0, eth1) |
| **UART** | On-chip 8250/16550 | `ttyS0` @ MMIO `0x18147000`, IRQ 17 |
| **USB** | Realtek RTL819x EHCI + OHCI | EHCI @ `0x18021000`, OHCI @ `0x18020000`, shared IRQ 21 |

### Factory identity (from this unit)

| Item | Value |
|---|---|
| MAC (eth0 / br-lan) | `AC:A7:F1:93:C7:40` |
| MAC (wlan0, 5 GHz) | `AC:A7:F1:93:C7:3F` |
| MAC (wlan1, 2.4 GHz) | `AC:A7:F1:93:C7:3E` |
| Hostname | `TL-WR1502X` |
| Product name | `AX1500 Wi-Fi 6 Portable Router` |
| Special ID | `55530000` (US region) |
| Region code (runtime) | `DE` (Germany) |

---

## Firmware Format

The firmware image (`wr1502xv1-v1.6-up-all-ver1-1-1-P1[...].bin`, ~18 MB) has the
following structure:

| Offset | Content |
|---|---|
| `0x0000` | `fw-type:Cloud` header (~1 KB) |
| `0x3A38` | LZMA-compressed kernel |
| `0x43AA42` | SquashFS 4.0 filesystem (xz compressed) |
| End | RSA-2048 PSS signature (0x100 bytes) |

Key facts:

- **Signed, not encrypted.** The image is RSA-2048 PSS signed by TP-Link,
  verified by U-Boot at boot. The body is plaintext.
- **The signature uses the public key** `l_rsa2048PubKey` embedded in the
  `tplink_decrypt` tool (extracted from `fw-type:Cloud` handling).
- **GPL source available** from TP-Link for the RTL8197 platform.
- **Kernel:** Linux 4.4.176, built with Realtek MSDK-6.4.1 (gcc 6.4.1).
- **Rootfs:** SquashFS 4.0 with xz compression.

### Lua bytecode quirk

The vendor ships Lua 5.1 bytecode with a **modified header flag byte** at
offset 11 set to `0x04` instead of the standard `0x00`/`0x01`. Standard
`luac`/`luadec` reject the file. Patching the byte to `0x00` allows normal
parsing.

```bash
# Patch the vendor Lua bytecode for analysis
cp crypto.lua /tmp/crypto.fixed.lua
printf '\x00' | dd of=/tmp/crypto.fixed.lua bs=1 seek=11 count=1 conv=notrunc
```

---

## Partition Layout

Runtime partition layout, from the U-Boot boot log:

| Offset | Size | Name | Notes |
|---|---|---|---|
| `0x0000000` | 1 MB | `uboot` | U-Boot bootloader, v3.4.13 |
| `0x0100000` | 1 MB | *(factory data)* | MAC, device-id, tss_key (implicit, not shown in /proc/mtd) |
| `0x0200000` | 1 MB | `u-boot-env` | U-Boot environment |
| `0x0300000` | 10 MB | `uImage` | Kernel image 0 |
| `0x0D00000` | 30 MB | `rootfs` | SquashFS rootfs 0 |
| `0x2B00000` | 10 MB | `uImage_1` | Kernel image 1 (dual-image) |
| `0x3500000` | 30 MB | `rootfs_1` | SquashFS rootfs 1 |
| `0x5300000` | 20 MB | `userconfig` | UBI volume (2 sub-volumes: `user_data1`, `user_data2`) |
| `0x6700000` | 10 MB | `tp_data` | UBI volume (`tp_data`) |

**Dual-image boot:** the bootloader prefers image 0; if signature
verification fails, it falls back to image 1.

---

## Boot Sequence

Confirmed from UART boot log (115200 8N1).

```
Realtek RTL8197F-VG boot code v3.4.13 (999MHz)
SPI Nand ID=0000c801  (ESMT F50L1G41LB)
[TP_DUAL_IMAGE] find dual image in 0x00300000 / 0x02B00000, boot from image 1
Jump to image start=0x81000000...
Linux version 4.4.176 (Realtek MSDK-6.4.1)

Kernel command line:
  root=/dev/mtdblock5 console=ttyS0,115200 init=/etc/preinit

8 rtkxxpart partitions found
Creating 8 MTD partitions on "rtk_nand"  (see layout above)

...
Please press Enter to activate this console.
```

**Kernel command line:** `root=/dev/mtdblock5 console=ttyS0,115200 init=/etc/preinit`

**Boot partition used:** image 1 (`0x02B00000`), kernel + rootfs pair.

---

## Findings

### Finding 1 — TDP authentication token from public DEV_ID

**Component:** `usr/bin/tdpServer`
**CWE:** 330, 287
**CVSS 3.1:** 8.1 (`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)

The TDP protocol daemon (`tdpServer`) computes the Tether app's
authentication token as:

```
token = MD5("TETHER_KEY_V1_" + DEV_ID)
```

`DEV_ID` is a 6-byte factory identifier stored in the `device-id` NVRAM
partition, read via `/sbin/getfirm DEV_ID`.

**The router discloses `DEV_ID` to any LAN client** in its own TDP discovery
response (field 9), in the same message that carries the derived token
(field 16).

**A per-device secret partition exists** (`tss_key`, partition 26 in the
factory table) but is not used by this code path.

When `DEV_ID` reads empty (blank flash, failed read, recovery boot), the
token becomes the constant:

```
MD5("TETHER_KEY_V1_") = 022e1ad97e0441d9c3e30cd6031d03b9
```

**Disassembly evidence** (annotated excerpt):

```asm
; helper at 0x40abac fetches DEV_ID via /sbin/getfirm DEV_ID
40abc8: addiu   v0,v0,-4716      ; "DEV_ID"
40abd0: addiu   a2,a2,-4892      ; "/sbin/getfirm"

; build the token string
40b0ec: lui     a1,0x41
40b0f0: addiu   a2,sp,148        ; a2 = DEV_ID buffer
40b0f4: addiu   a1,a1,-4696      ; a1 = "TETHER_KEY_V1_(%s)"
40b100: jal     sprintf@plt

40b11c: jal     4028fc           ; MD5
40b128: li      a1,16
40b12c: jal     40888c           ; append as field 16

; field 9 is populated from the same DEV_ID buffer
40b0d8: li      a1,9
40b0dc: jal     4087a4           ; append field 9 (DEV_ID)
```

**Impact:** any LAN-adjacent attacker who observes or triggers a TDP
discovery request receives `DEV_ID` and can compute the token. The token has
no session binding, nonce, or expiry at computation time, functioning as a
reusable bearer credential for TDP write operations including
`tmp_insert_vpn_server_account`, `tmp_set_filter`, `tmp_timing_reboot`, and
others.

**Suggested fix:** derive the TDP token from `tss_key` or another
factory-provisioned secret; prefer nonce-based challenge-response; remove
the constant fallback.

---

### Finding 2 — Static AES key for stored credentials

**Component:** `usr/lib/lua/luci/model/crypto.lua` (compiled Lua 5.1 bytecode)
**CWE:** 321, 329
**CVSS 3.1:** 6.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)

Stored credentials are encrypted with AES-256-CBC using constants that are
identical across every unit of this model and present in the publicly
distributed firmware image:

| Parameter | Value |
|---|---|
| Cipher | `aes-256-cbc` |
| KDF | OpenSSL legacy `EVP_BytesToKey` MD5 |
| Passphrase | `2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836` |
| IV (hex) | `360028C9064242F81074F4C127D299F6` |
| Pre-processing | zlib compress |
| Encoding | base64 |

A secondary code path references `-kfile /etc/secretkey`, but that file
does not exist on this model.

**Impact:** any captured credential blob (from a config backup, a flash
dump, or a field-encrypted value) is decryptable using only the publicly
available firmware image.

**Suggested fix:** generate a per-device AES key at first boot and store it
in protected NVRAM. Do not ship the key inside the firmware.

---

### Finding 3 — Configuration backup decryptable

**Component:** Config backup / restore path
**CWE:** 321, 311
**CVSS 3.1:** 7.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)

Every config backup (`backup-TL-WR1502X-<date>.bin`) is a nested container
encrypted under the same static AES key as Finding 2. The chain, verified
end-to-end on a real unit:

```
backup.bin
  → AES-256-CBC decrypt (raw key, no padding, no salt)
  → zlib decompress
  → 16-byte header || tar archive
  → tar extract
  → ori-backup-user-config.bin
  → AES-256-CBC decrypt (same key)
  → zlib decompress
  → XML configuration with credentials in cleartext
```

**Recovered from a real backup:**

| Field | Format |
|---|---|
| Wi-Fi PSK (2.4G + 5G + guest) | Cleartext |
| WPS PIN | Cleartext (identical to PSK) |
| OpenVPN server password | Cleartext |
| Cloud `accessKey` | Cleartext (32 hex) |
| Cloud `accessSecret` | Cleartext (32 hex) |
| Admin password | 10-byte truncated hash |
| Router MAC | Cleartext |

**Impact:** any party in possession of a backup file (and the publicly
available firmware) can recover all stored credentials.

**Suggested fix:** reuse the per-device key from Finding 2. Ensure the
backup layer does not rely on any value shipped in the firmware.

---

### Finding 4 — Modified backup accepted without integrity check

**Component:** Config restore path
**CWE:** 345
**CVSS 3.1:** 5.5 (`AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`)

Configuration backups are applied by the router without any signature,
checksum, or integrity verification. A backup repacked with modified XML
(preserving the original 16-byte header) restored successfully, changing
system configuration values including the hostname and firewall zone names.

**Impact:** an attacker with write access to a backup file can alter stored
configuration on the target device. Where config fields are later consumed
by shell commands, this can lead to code execution.

**Reproduction confirmed:** modified hostname and firewall zone name were
applied after a backup restore; no signature check occurred.

**Suggested fix:** sign config backups with a per-device key or the factory
RSA key. Verify on restore. Reject modified backups.

---

## Reproduction

### 1. Decrypt a config backup

Export a backup from the web UI (**System → Backup & Restore**). Then:

```bash
python3 tplink_wr1502x_decrypt.py backup-TL-WR1502X-*.bin -o config.xml
python3 tplink_wr1502x_decrypt.py backup-TL-WR1502X-*.bin --credentials
python3 tplink_wr1502x_decrypt.py backup-TL-WR1502X-*.bin --device-info -v
```

### 2. Compute the Tether token from a DEV_ID

```bash
python3 verify_tether_token.py --dev-id 0123456789ab
```

### 3. Round-trip test the crypto

```bash
KEY=2EB38F7EC41D4B8E1422805BCD5F740BC3B95BE163E39D67579EB344427F7836
IV=360028C9064242F81074F4C127D299F6

echo -n "test" \
  | openssl zlib -e \
  | openssl enc -aes-256-cbc -e -nosalt -K $KEY -iv $IV \
  | base64
```

### 4. Repack a modified backup

```bash
python3 repack_backup.py modified.xml original-backup.bin -o new-backup.bin
```

---

## Tooling

All scripts are self-contained (Python 3 standard library + openssl).

### `tplink_wr1502x_decrypt.py` — backup decryptor

Extracts and decrypts a TL-WR1502X config backup to XML. Supports:

- `--credentials` — print all credential fields found
- `--redact` — replace sensitive values with `REDACTED`
- `--device-info` — show model, firmware, hostname, MAC
- `-o FILE` — write output to a file

### `verify_tether_token.py` — TDP token computer

Takes a `DEV_ID` and prints `MD5("TETHER_KEY_V1_" + DEV_ID)`.

### `repack_backup.py` — backup repacker

Takes a modified XML and an original backup, produces a new backup file
suitable for restoring via the web UI.

### `router_uart.py` — UART reconnaissance (Windows / Linux)

Sends recon commands to the router over UART. Requires `pyserial`.

---

## UART Access

The router exposes a UART console on a 4-pin header on the PCB.

**Wiring:**

```
Router TX  →  Adapter RX
Router RX  →  Adapter TX
Router GND →  Adapter GND
Router VCC →  (do NOT connect)
```

**Voltage:** 3.3V logic. Do not use a 5V adapter without a level shifter.

**Terminal:** 115200 baud, 8N1, no flow control.

```
Console:  ttyS0 (8250/16550, IRQ 17, MMIO 0x18147000)
```

**Expected:** boot log scrolls, then:

```
Please press Enter to activate this console.
```

Press Enter → shell prompt.

**Known issue:** CH341A in serial mode often fails to transmit (RX works,
TX doesn't). Use a CP2102/CH340/FT232 for reliable UART.

**Diagnostic:** with the CH341A's TXD and RXD shorted together (loopback),
does typed text echo back? If not, the adapter's TX is broken.

---

## Flash Dump

The flash chip is an ESMT F50L1G41LB SPI NAND (128 MB).

**Tools:** SNANDer (McMCCRU) with CH341A in SPI mode.

**Procedure:**

1. Power off the router.
2. Switch CH341A to SPI mode.
3. Attach SOIC-8 clip to the NAND (pin 1 aligned).
4. Detect and read:

```bash
sudo SNANDer -i                    # detects ESMT F50L1G41LB
sudo SNANDer -r firmware-dump.bin  # 128 MB, ~5-15 min
```

5. Verify size (134,217,728 bytes) and back up twice.

**Partitions to carve:**

```bash
dd if=firmware-dump.bin of=uboot.bin   bs=1 skip=$((0x0000000)) count=$((0x0100000))
dd if=firmware-dump.bin of=rootfs.bin  bs=1 skip=$((0x0d00000)) count=$((0x1e00000))
dd if=firmware-dump.bin of=factory.bin bs=1 skip=$((0x100000))  count=$((0x100000))
```

**What the dump provides that UART cannot:**

- U-Boot binary (for signature-bypass analysis)
- Full rootfs (both images)
- Factory data: `device-id`, `tss_key`, `special_id`, MAC addresses
- Wi-Fi calibration data
- A complete recovery image in case of brick

---

## Mitigations

### For end users

- Restrict LAN access to trusted devices.
- Enable guest-network isolation.
- Rotate Wi-Fi, admin, VPN, and cloud passwords periodically.
- Delete old config backups; avoid exporting to untrusted storage.
- Do not share config backups by email or cloud storage.

### For TP-Link

| Finding | Fix |
|---|---|
| 1 — TDP token | Derive from `tss_key`; use nonce-based challenge-response; remove constant fallback token |
| 2 — Static AES key | Per-device key generated at first boot, stored in protected NVRAM |
| 3 — Backup decryption | Reuse the per-device key from Finding 2 for backups |
| 4 — Unverified restore | Sign backups; verify signature on restore |

---

## References

- **Firmware image:** `wr1502xv1-v1.6-up-all-ver1-1-1-P1[20250808-rel68172]_sign_2025-08-08_19.15.54.zip`
- **GPL source:** `GPL_TL-WR1502Xv1.tar.gz` (from TP-Link support site)
- **U-Boot:** Realtek RTL8197F-VG boot code v3.4.13 (2024.10.29)
- **Kernel:** Linux 4.4.176, Realtek MSDK-6.4.1, gcc 6.4.1
- **Tooling used:** `binwalk`, `sasquatch`, `unsquashfs`, `mipsel-linux-gnu-objdump`, Ghidra, `luadec51`, `tplink_decrypt`, `SNANDer`, `pyserial`, `openssl`

---

## License

Analysis and tooling released under MIT. Findings under CC BY 4.0.

## Contact

Researcher: **Nguyen Vu Ha**
Email: hanaloginstruments@gmail.com
Country: Vietnam
Affiliation: Independent researcher

Disclosure submitted to TP-Link Product Security (`security@tp-link.com`),
requesting coordinated disclosure with 90-day timeline.
