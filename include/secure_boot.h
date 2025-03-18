#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "sha256.h"
#include "pmp_isolation.h"

#define BOOT_MAGIC 0x53424F54 // "SBOT" (Secure Boot)
#define MAX_PAYLOAD_SIZE 65536

// Cryptographic Image Header
typedef struct __attribute__((packed)) {
    uint32_t magic;              // "SBOT"
    uint32_t version;            // Firmware version (Anti-rollback check)
    uint32_t payload_size;       // Size in bytes
    uint32_t target_load_addr;   // Target RAM entry address
    uint8_t  expected_hash[SHA256_DIGEST_SIZE]; // Signed digest
    uint8_t  signature_sim[32];  // Mocked HMAC/ECDSA digital signature token
} fw_image_header_t;

typedef enum {
    BOOT_SUCCESS = 0,
    ERR_INVALID_MAGIC,
    ERR_VERSION_ROLLBACK,
    ERR_PAYLOAD_OVERFLOW,
    ERR_INTEGRITY_MISMATCH,
    ERR_SIGNATURE_INVALID,
    ERR_PMP_TRAP
} boot_status_t;

typedef struct {
    uint32_t minimum_anti_rollback_version;
    uint8_t  root_of_trust_public_key_hash[SHA256_DIGEST_SIZE];
    pmp_controller_t pmp;
} secure_bootloader_state_t;

void bootloader_init(secure_bootloader_state_t *state, uint32_t min_version);
boot_status_t bootloader_verify_and_stage(
    secure_bootloader_state_t *state,
    const fw_image_header_t *header,
    const uint8_t *payload_bytes,
    uintptr_t destination_ram
);
const char* boot_status_str(boot_status_t status);
