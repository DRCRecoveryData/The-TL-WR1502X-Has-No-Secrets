# TL-WR1502X v1.0 — Firmware Analysis & Security Research

Analysis of the TP-Link TL-WR1502X v1.0 portable Wi-Fi 6 router (AX1500 class),
firmware version 1.2.11 Build 20251009 rel.56489(4555).

Four confirmed security findings, with reproduction tooling, evidence, and a
verified flash dump for recovery.

---

## Table of Contents

- [Hardware](#hardware)
- [Firmware Format](#firmware-format)
- [Partition Layout](#partition-layout)
- [Boot Sequence](#boot-sequence)
- [Findings](#findings)
- [Reproduction](#reproduction)
- [Tooling](#tooling)
- [UART Access](#uart-access)
- [Flash Dump](#flash-dump)
- [Flash Write-Back](#flash-write-back)
- [Where DEV_ID and MAC Live](#where-dev_id-and-mac-live)
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
| **OTP / EFUSE** | Integrated in RTL8197F | Stores MAC, DEV_ID, tss_key, calibration |

### MAC addresses (from web UI)

| Interface | MAC |
|---|---|
| br-lan / eth0 | `AC:A7:F1:93:C7:40` |
| wlan0 (5 GHz) | `AC:A7:F1:93:C7:3F` |
| wlan1 (2.4 GHz) | `AC:A7:F1:93:C7:3E` |

**Note:** The above MACs were observed via the web UI. They are **not present in
the flash dump**. See [Where DEV_ID and MAC Live](#where-dev_id-and-mac-live).

---

## Firmware Format

The downloadable firmware image (`wr1502xv1-v1.6-up-all-ver1-1-1-P1[...].bin`,
~18 MB) has the following structure:

| Offset | Content |
|---|---|
| `0x0000` | `fw-type:Cloud` header (~1 KB) |
| `0x3A38` | LZMA-compressed kernel |
| `0x43AA42` | SquashFS 4.0 filesystem (xz compressed) |
| End | RSA-2048 PSS signature (0x100 bytes) |

Key facts:

- **Signed, not encrypted.** The image is RSA-2048 PSS signed by TP-Link and
  verified by U-Boot at boot. The body is plaintext.
- **Kernel:** Linux 4.4.176, built with Realtek MSDK-6.4.1 (gcc 6.4.1).
- **Rootfs:** SquashFS 4.0 with xz compression.
- **GPL source** available from TP-Link for the RTL8197 platform.

### Lua bytecode quirk

The vendor ships Lua 5.1 bytecode with a **modified header flag byte** at
offset 11 set to `0x04` instead of the standard `0x00`/`0x01`. Standard
`luac`/`luadec` reject the file. Patching the byte to `0x00` allows normal
parsing.

```bash
cp crypto.lua /tmp/crypto.fixed.lua
printf '\x00' | dd of=/tmp/crypto.fixed.lua bs=1 seek=11 count=1 conv=notrunc
