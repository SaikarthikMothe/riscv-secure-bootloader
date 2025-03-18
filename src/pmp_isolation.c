#include "pmp_isolation.h"
#include <stdio.h>
#include <string.h>

void pmp_init(pmp_controller_t *ctrl) {
    memset(ctrl, 0, sizeof(pmp_controller_t));
}

bool pmp_configure_region(pmp_controller_t *ctrl, size_t entry_idx, uintptr_t start, uintptr_t end, uint8_t flags, const char* name) {
    if (entry_idx >= MAX_PMP_ENTRIES) return false;
    
    // If already locked, PMP forbids modification until system reset
    if (ctrl->regions[entry_idx].locked) {
        printf("[PMP SECURITY FAULT] Attempted to alter locked PMP entry %zu!\n", entry_idx);
        return false;
    }

    ctrl->regions[entry_idx].addr_start = start;
    ctrl->regions[entry_idx].addr_end = end;
    ctrl->regions[entry_idx].cfg_flags = flags;
    ctrl->regions[entry_idx].locked = (flags & PMP_L) != 0;
    ctrl->regions[entry_idx].region_name = name;
    
    if (entry_idx >= ctrl->count) {
        ctrl->count = entry_idx + 1;
    }
    return true;
}

bool pmp_check_access(const pmp_controller_t *ctrl, uintptr_t target_addr, uint8_t requested_access, bool is_machine_mode) {
    // Check lowest matching index in PMP table
    for (size_t i = 0; i < ctrl->count; ++i) {
        const pmp_region_t *r = &ctrl->regions[i];
        if (target_addr >= r->addr_start && target_addr < r->addr_end) {
            // Machine mode bypasses unlocked entries, but locked entries apply even to M-mode
            if (is_machine_mode && !r->locked) {
                return true;
            }
            // Check access flags: Read, Write, Execute
            if ((requested_access & r->cfg_flags) == requested_access) {
                return true;
            } else {
                return false; // Hardware fault trap triggered
            }
        }
    }
    // Default fallback in RISC-V: If no rule matches, M-mode allowed, lower modes trap
    return is_machine_mode;
}

void pmp_dump_configuration(const pmp_controller_t *ctrl) {
    printf("\n================= RISC-V PMP Memory Protection Map =================\n");
    for (size_t i = 0; i < ctrl->count; ++i) {
        const pmp_region_t *r = &ctrl->regions[i];
        printf(" [PMP #%02zu] 0x%08llx - 0x%08llx | %c%c%c%c | %s\n",
               i,
               (unsigned long long)r->addr_start,
               (unsigned long long)r->addr_end,
               (r->cfg_flags & PMP_R) ? 'R' : '-',
               (r->cfg_flags & PMP_W) ? 'W' : '-',
               (r->cfg_flags & PMP_X) ? 'X' : '-',
               (r->cfg_flags & PMP_L) ? 'L' : '-',
               r->region_name ? r->region_name : "UNNAMED");
    }
    printf("====================================================================\n\n");
}
