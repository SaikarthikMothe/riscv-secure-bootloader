#include "secure_boot.h"
#include <stdio.h>
#include <string.h>

void bootloader_init(secure_bootloader_state_t *state, uint32_t min_version) {
    memset(state, 0, sizeof(secure_bootloader_state_t));
    state->minimum_anti_rollback_version = min_version;

    // Hardcoded Root of Trust public key digest (simulating one-time programmable eFuses)
    const uint8_t mock_efuse_rot[SHA256_DIGEST_SIZE] = {
        0x10, 0x24, 0x9a, 0xef, 0x55, 0xaa, 0x33, 0x77,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    memcpy(state->root_of_trust_public_key_hash, mock_efuse_rot, SHA256_DIGEST_SIZE);

    // Initialize PMP controller:
    // Region 0: Secure Boot ROM & Keystore [0x00010000 - 0x00020000] Read-Only, Locked
    pmp_init(&state->pmp);
    pmp_configure_region(&state->pmp, 0, 0x00010000, 0x00020000, PMP_R | PMP_X | PMP_L, "SECURE_ROM_KEYSTORE");

    // Region 1: Stage-2 Firmware Payload RAM [0x80000000 - 0x80100000] Read-Write-Execute
    pmp_configure_region(&state->pmp, 1, 0x80000000, 0x80100000, PMP_R | PMP_W | PMP_X, "FW_PAYLOAD_RAM");

    // Region 2: Hardware Mailbox / MMIO Control [0x10000000 - 0x10001000] Read-Write
    pmp_configure_region(&state->pmp, 2, 0x10000000, 0x10001000, PMP_R | PMP_W, "MMIO_MAILBOX");
}

boot_status_t bootloader_verify_and_stage(
    secure_bootloader_state_t *state,
    const fw_image_header_t *header,
    const uint8_t *payload_bytes,
    uintptr_t destination_ram
) {
    printf("[SECURE BOOT] Inspecting image header...\n");

    // 1. Validate Magic Number
    if (header->magic != BOOT_MAGIC) {
        printf("[FAIL] Invalid Magic: 0x%08X (Expected: 0x%08X)\n", header->magic, BOOT_MAGIC);
        return ERR_INVALID_MAGIC;
    }

    // 2. Anti-Rollback Monotonic Version Check
    if (header->version < state->minimum_anti_rollback_version) {
        printf("[FAIL] Anti-rollback violation! Image version %u < Minimum allowed %u\n",
               header->version, state->minimum_anti_rollback_version);
        return ERR_VERSION_ROLLBACK;
    }

    // 3. Size Bounds & Buffer Overflow Check
    if (header->payload_size > MAX_PAYLOAD_SIZE || header->payload_size == 0) {
        printf("[FAIL] Illegal payload size: %u bytes\n", header->payload_size);
        return ERR_PAYLOAD_OVERFLOW;
    }

    // 4. Cryptographic Hash & Integrity Verification (SHA-256)
    uint8_t actual_digest[SHA256_DIGEST_SIZE];
    sha256_hash(payload_bytes, header->payload_size, actual_digest);

    if (memcmp(actual_digest, header->expected_hash, SHA256_DIGEST_SIZE) != 0) {
        printf("[FAIL] SHA-256 Digest Mismatch! Payload has been corrupted or tampered with.\n");
        return ERR_INTEGRITY_MISMATCH;
    }
    printf("[PASS] Cryptographic SHA-256 Integrity Verified.\n");

    // 5. Digital Signature Token Check (Simulated eFuse validation)
    uint8_t expected_sig[32];
    for (int i = 0; i < 32; ++i) {
        expected_sig[i] = actual_digest[i] ^ state->root_of_trust_public_key_hash[i];
    }
    if (memcmp(expected_sig, header->signature_sim, 32) != 0) {
        printf("[FAIL] Digital Signature Validation Failed! Untrusted signing key.\n");
        return ERR_SIGNATURE_INVALID;
    }
    printf("[PASS] Digital Signature Verified via Root of Trust.\n");

    // 6. Verify Target RAM address against PMP isolation boundaries
    if (!pmp_check_access(&state->pmp, destination_ram, PMP_W, false)) {
        printf("[FAIL] Hardware PMP violation attempting to write destination RAM 0x%llx!\n", (unsigned long long)destination_ram);
        return ERR_PMP_TRAP;
    }

    printf("[STAGE] Copying verified firmware into target RAM at 0x%llx (%u bytes)...\n",
           (unsigned long long)destination_ram, header->payload_size);
    printf("[BOOT] Firmware verified successfully! Handing off execution to entry point.\n\n");
    return BOOT_SUCCESS;
}

const char* boot_status_str(boot_status_t status) {
    switch (status) {
        case BOOT_SUCCESS: return "BOOT_SUCCESS";
        case ERR_INVALID_MAGIC: return "ERR_INVALID_MAGIC";
        case ERR_VERSION_ROLLBACK: return "ERR_VERSION_ROLLBACK";
        case ERR_PAYLOAD_OVERFLOW: return "ERR_PAYLOAD_OVERFLOW";
        case ERR_INTEGRITY_MISMATCH: return "ERR_INTEGRITY_MISMATCH";
        case ERR_SIGNATURE_INVALID: return "ERR_SIGNATURE_INVALID";
        case ERR_PMP_TRAP: return "ERR_PMP_TRAP";
        default: return "UNKNOWN_ERROR";
    }
}
