# RISC-V Secure Bootloader & Hardware PMP Isolation Engine

A bare-metal secure bootloader and Physical Memory Protection (PMP) hardware isolation engine designed for embedded security microcontrollers, on-chip controllers, and system-on-chip (SoC) environments. The project implements multi-stage firmware authentication, cryptographic Root-of-Trust (RoT) key attestation, anti-rollback protection, and hardware-enforced memory isolation.

---

## Architectural Design

The bootloader follows a defense-in-depth architecture executing across reset, validation, isolation, and execution stages:

```
[ Power-On Reset ]
        │
        ▼
[ Read Hardware eFuses ] ──► Load Root-of-Trust Public Key Hash
        │
        ▼
[ Configure & Lock PMP ] ──► Enforce Read-Only / Execute on Secure ROM (Locked)
        │                    Configure RW on MMIO & Payload RAM
        ▼
[ Validate Header ]      ──► Magic Number (0x53424F54) & Payload Size Bounds
        │
        ▼
[ Anti-Rollback Check ]  ──► Assert Firmware Version >= Monotonic Security Counter
        │
        ▼
[ Cryptographic SHA-256] ──► Verify Payload Digest against Signed Header
        │
        ▼
[ Signature Attestation] ──► Verify Digital Signature Token against RoT Key
        │
        ▼
[ PMP Boundary Staging ] ──► Validate Staging Memory Address Against PMP Rules
        │
        ▼
[ Execution Handover ]   ──► Jump to Authenticated Firmware Entry Point
```

---

## Core Components

### 1. Multi-Stage Secure Boot Verification (`secure_boot.c`)
- **Magic Number Validation**: Verifies `0x53424F54` ('SBOT') header signature before processing.
- **Anti-Rollback Version Protection**: Rejects firmware binaries with version counters below the device's monotonic minimum version, mitigating downgrade attacks.
- **Size Bounds Checking**: Restricts payload dimensions to prevent buffer overflow vulnerabilities during image staging.
- **Cryptographic Hash Verification**: Employs standalone SHA-256 hashing to assert exact payload integrity against bit-flips or deliberate tampering.
- **Root-of-Trust (RoT) Signature Attestation**: Authenticates image signatures against an immutable Root-of-Trust key digest (simulating one-time programmable eFuses).

### 2. RISC-V Physical Memory Protection (PMP) (`pmp_isolation.c`)
- Implements the RISC-V Privileged Architecture PMP specification to enforce hardware memory boundaries:
  - **Secure ROM / Keystore** (`0x00010000 - 0x00020000`): Marked Read-Only and Executable (`PMP_R | PMP_X`) with the Lock bit (`PMP_L`) set. Once configured, modification is prevented by hardware until system reset.
  - **Firmware Payload RAM** (`0x80000000 - 0x80100000`): Granted Read, Write, and Execute (`PMP_R | PMP_W | PMP_X`) for authenticated runtime code.
  - **Hardware Mailbox MMIO** (`0x10000000 - 0x10001000`): Configured Read and Write (`PMP_R | PMP_W`) for inter-processor messaging.

### 3. Standalone SHA-256 Cryptographic Engine (`sha256.c`)
- Zero-dependency, pure C implementation optimized for bare-metal boot ROM environments without standard C library runtime requirements.

---

## Repository Structure

```
.
├── include/
│   ├── pmp_isolation.h       # RISC-V PMP controller structures & permission flags
│   ├── secure_boot.h         # Firmware header definitions & boot state machine
│   └── sha256.h              # Standalone SHA-256 cryptographic interface
├── src/
│   ├── pmp_isolation.c       # PMP boundary configuration & access checking
│   ├── secure_boot.c         # Bootloader authentication & staging logic
│   └── sha256.c              # SHA-256 transformation & hashing routines
├── tests/
│   └── test_secure_boot.c    # Verification testbench & negative testing suite
├── bin/
│   └── secure_boot_test.exe  # Compiled test binary
└── README.md
```

---

## Security Verification Testbench

The test suite (`test_secure_boot.c`) validates functional and fault-handling behaviors across five test cases:

1. **Legitimate Firmware Image Authentication**: Validates correct hash, signature, and staging into authorized memory.
2. **Anti-Rollback Exploit Injection**: Attempts staging a revoked (older) version; traps with `ERR_VERSION_ROLLBACK`.
3. **Payload Bit-Flip Tampering**: Inverts a single payload byte; traps with `ERR_INTEGRITY_MISMATCH`.
4. **Counterfeit Signature Token**: Simulates an unauthorized signing key; traps with `ERR_SIGNATURE_INVALID`.
5. **PMP Boundary Access Violation**: Attempts staging code directly into the Locked Keystore ROM; hardware access check triggers `ERR_PMP_TRAP`.

---

## Build and Execution

```bash
# Compile using GCC / Clang
gcc -O2 -I include src/sha256.c src/pmp_isolation.c src/secure_boot.c tests/test_secure_boot.c -o bin/secure_boot_test.exe

# Execute verification test suite
./bin/secure_boot_test.exe
```
