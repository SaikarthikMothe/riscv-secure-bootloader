#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * RISC-V Physical Memory Protection (PMP) Configuration
 * According to RISC-V Privileged Architecture Specification
 */
#define PMP_R     (1 << 0) // Read permit
#define PMP_W     (1 << 1) // Write permit
#define PMP_X     (1 << 2) // Execute permit
#define PMP_A_OFF (0 << 3) // Null / Disabled
#define PMP_A_TOR (1 << 3) // Top of Range
#define PMP_A_NA4 (2 << 3) // Naturally aligned 4-byte
#define PMP_A_NAPOT (3 << 3) // Naturally aligned power-of-two
#define PMP_L     (1 << 7) // Lock register (Permanent until reset)

#define MAX_PMP_ENTRIES 16

typedef struct {
    uintptr_t addr_start;
    uintptr_t addr_end;
    uint8_t   cfg_flags;
    bool      locked;
    const char* region_name;
} pmp_region_t;

typedef struct {
    pmp_region_t regions[MAX_PMP_ENTRIES];
    size_t count;
} pmp_controller_t;

void pmp_init(pmp_controller_t *ctrl);
bool pmp_configure_region(pmp_controller_t *ctrl, size_t entry_idx, uintptr_t start, uintptr_t end, uint8_t flags, const char* name);
bool pmp_check_access(const pmp_controller_t *ctrl, uintptr_t target_addr, uint8_t requested_access, bool is_machine_mode);
void pmp_dump_configuration(const pmp_controller_t *ctrl);
