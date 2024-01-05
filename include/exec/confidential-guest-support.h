/*
 * QEMU Confidential Guest support
 *   This interface describes the common pieces between various
 *   schemes for protecting guest memory or other state against a
 *   compromised hypervisor.  This includes memory encryption (AMD's
 *   SEV and Intel's MKTME) or special protection modes (PEF on POWER,
 *   or PV on s390x).
 *
 * Copyright Red Hat.
 *
 * Authors:
 *  David Gibson <david@gibson.dropbear.id.au>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */
#ifndef QEMU_CONFIDENTIAL_GUEST_SUPPORT_H
#define QEMU_CONFIDENTIAL_GUEST_SUPPORT_H

#ifndef CONFIG_USER_ONLY

#include "qom/object.h"
#include "exec/hwaddr.h"

#if defined(CONFIG_IGVM)
#include "igvm/igvm.h"
#endif

#if defined(CONFIG_IGVM)
#include "igvm/igvm.h"
#endif

#define TYPE_CONFIDENTIAL_GUEST_SUPPORT "confidential-guest-support"
OBJECT_DECLARE_SIMPLE_TYPE(ConfidentialGuestSupport, CONFIDENTIAL_GUEST_SUPPORT)

typedef enum ConfidentialGuestPlatformType {
    CGS_SEV_SNP
} ConfidentialGuestPlatformType;

typedef enum ConfidentialGuestMemoryType {
    CGS_MEM_RAM,
    CGS_MEM_RESERVED,
    CGS_MEM_ACPI,
    CGS_MEM_NVS,
    CGS_MEM_UNUSABLE,
} ConfidentialGuestMemoryType;

typedef struct ConfidentialGuestMemoryMapEntry {
    uint64_t gpa;
    uint64_t size;
    ConfidentialGuestMemoryType type;
} ConfidentialGuestMemoryMapEntry;

struct ConfidentialGuestSupport {
    Object parent;

    /*
     * ready: flag set by CGS initialization code once it's ready to
     *        start executing instructions in a potentially-secure
     *        guest
     *
     * The definition here is a bit fuzzy, because this is essentially
     * part of a self-sanity-check, rather than a strict mechanism.
     *
     * It's not feasible to have a single point in the common machine
     * init path to configure confidential guest support, because
     * different mechanisms have different interdependencies requiring
     * initialization in different places, often in arch or machine
     * type specific code.  It's also usually not possible to check
     * for invalid configurations until that initialization code.
     * That means it would be very easy to have a bug allowing CGS
     * init to be bypassed entirely in certain configurations.
     *
     * Silently ignoring a requested security feature would be bad, so
     * to avoid that we check late in init that this 'ready' flag is
     * set if CGS was requested.  If the CGS init hasn't happened, and
     * so 'ready' is not set, we'll abort.
     */
    bool ready;

#if defined(CONFIG_IGVM)
    /*
     * igvm_filename: Optional filename that specifies a file that contains
     *                the configuration of the guest in Isolated Guest 
     *                Virtual Machine (IGVM) format.
     */
    char *igvm_filename;
    IgvmHandle igvm;
#endif

    /*
     * The following virtual methods need to be implemented by systems that
     * support confidential guests that can be configured with IGVM and are
     * used during processing of the IGVM file with process_igvm().
     */

    /*
     * Check for to see if this confidential guest supports a particular
     * platform or configuration
     */
    int (*check_support)(ConfidentialGuestPlatformType platform,
                         uint16_t platform_version, uint8_t highest_vtl,
                         uint64_t shared_gpa_boundary);

    /* 
     * Configure an area of guest memory, populating the guest memory with
     * with the data in the provided pointer at the requested guest physical
     * address. Memory type is one of KVM_SEV_SNP_PAGE_TYPE_*.
     */
    int (*set_memory_attributes)(hwaddr gpa, uint8_t *ptr, uint64_t len,
                                 int memory_type);

    /*
     * Set the initial context for a virtual CPU. The format of the context pointed
     * to by ctx depends on the type of confidential virtual machine. For example,
     * for SEV-SNP, ctx points to a vmcb_save_area structure.
     */
    int (*set_cpu_context)(uint16_t cpu_index, const void *ctx,
                           uint32_t ctx_len);

    /*
     * Get the number of entries that should be populated into the guest memory map.
     */
    int (*get_mem_map_count)(void);

    /*
     * Get an entry that should be populated in the guest memory map.
     */
    void (*get_mem_map_entry)(int index,
                              ConfidentialGuestMemoryMapEntry *entry);
};

typedef struct ConfidentialGuestSupportClass {
    ObjectClass parent;
} ConfidentialGuestSupportClass;

#endif /* !CONFIG_USER_ONLY */

#endif /* QEMU_CONFIDENTIAL_GUEST_SUPPORT_H */
