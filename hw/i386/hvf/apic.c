/*
 * macOS Hypervisor.framework in-kernel APIC support
 */

#include "qemu/osdep.h"
#include "qom/object.h"
#include "hw/i386/apic_internal.h"
#include "hw/pci/msi.h"
#include "sysemu/hvf.h"
#include "sysemu/hvf_int.h"

#pragma mark DEBUG
#include <os/log.h>
#pragma mark -

// TODO: Move to general APIC header or use those defined in x2APIC patch series
#define MSR_IA32_APICBASE_FLAGS_X2APIC_ENABLED (MSR_IA32_APICBASE_EXTD | MSR_IA32_APICBASE_ENABLE)
#define MSR_IA32_APICBASE_FLAGS_MASK MSR_IA32_APICBASE_FLAGS_X2APIC_ENABLED
#define MSR_IA32_APICBASE_RESERVED_MASK (~(MSR_IA32_APICBASE_BASE | MSR_IA32_APICBASE_FLAGS_MASK | MSR_IA32_APICBASE_BSP))

#define TYPE_HVF_APIC "hvf-apic"
OBJECT_DECLARE_SIMPLE_TYPE(APICCommonState, HVF_APIC)

#define log(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ## __VA_ARGS__)

#pragma mark DEBUG
static const char* apic_dest_mode_str(uint8_t mode)
{
    switch (mode)
    {
    case 0: return "normal";
    case 1: return "lowest";
    case 2: return "SMI";
    case 3: return "reserved(3)";
    case 4: return "NMI";
    case 5: return "INIT";
    case 6: return "SIPI";
    case 7: return "reserved(7)";
    default: return "???";
    }
}

static const char* apic_dest_type_str(uint8_t mode)
{
    switch (mode)
    {
    case 0: return "normal";
    case 1: return "self";
    case 2: return "all";
    case 3: return "other";
    default: return "???";
    }
}
#pragma mark -


static void hvf_apic_send_msi(MSIMessage *msg)
{
    /* hv_vm_lapic_msi() wants the full GPA, not just the offset */
    uint64_t msi_address = msg->address | 0xfee00000;
    assert_hvf_ok(hv_vm_lapic_msi(msi_address, msg->data));
}

static MemTxResult hvf_apic_mem_read(void *opaque, hwaddr addr, uint64_t *data,
                                     unsigned size, MemTxAttrs attrs)
{
    hv_vcpuid_t vcpu;
    APICCommonState *s;
    uint32_t read_value;
    hv_return_t result;
    
    DeviceState *dev = cpu_get_current_apic();
    if (dev == NULL) {
#pragma mark DEBUG
        fprintf(stderr, "hvf_apic_mem_write: WARNING! No current APIC found, ignoring %u byte read from 0x%llx\n",
            size, addr);
        log("hvf_apic_mem_write: WARNING! No current APIC found, ignoring %u byte read from 0x%llx\n",
            size, addr);
#pragma mark -
        return MEMTX_ERROR;
    }

    s = APIC_COMMON(dev);

    /* MMIO only works when enabled and not in x2apic mode */
    if ((s->apicbase & MSR_IA32_APICBASE_FLAGS_MASK) != MSR_IA32_APICBASE_ENABLE || size != 4) {
        memset(data, 0xff, size);
#pragma mark DEBUG
        if (size != 4)
        {
            log("hvf_apic_mem_read[%u] addr = 0x%llx, size = %u -> bad size\n", s->initial_apic_id, addr, size);
        }
        else
        {
            log("hvf_apic_mem_read[%u/%u] addr = 0x%llx, size = %u; APICBASE = 0x%x -> bad flags 0x%x (APIC in x2APIC or not enabled, should be 0x%x)\n", s->initial_apic_id, CPU(s->cpu)->cpu_index, addr, size, s->apicbase, (s->apicbase & MSR_IA32_APICBASE_FLAGS_MASK), MSR_IA32_APICBASE_ENABLE);
            //log_backtrace(__FUNCTION__);
        }
#pragma mark -
        return MEMTX_ERROR;
    }

    vcpu = CPU(s->cpu)->accel->fd;
    read_value = ~UINT32_C(0);
    result = hv_vcpu_apic_read(vcpu, addr, &read_value);
    memcpy(data, &read_value, sizeof(read_value));

    if (result == HV_SUCCESS) {
#pragma mark DEBUG
        if (addr == 0x300) {
            uint32_t d = read_value;
            log("hvf_apic_mem_read[%u] ICR read: vector: 0x%02x, mode: %u (%{public}s), dest mode: %u, status: %u, init level deassert 0: %u, init level deassert 1: %u, destination type: %u (%{public}s), reserved: 0x%x\n",
            CPU(s->cpu)->cpu_index,
            d & 0xff,
            (d >> 8) & 0x7, apic_dest_mode_str((d >> 8) & 0x7),
            (d >> 11) & 0x1,
            (d >> 12) & 0x1,
            (d >> 14) & 0x1,
            (d >> 15) & 0x1,
            (d >> 18) & 0x3, apic_dest_type_str((d >> 18) & 0x3),
            (d & ((1u << 13) | (3u << 16) | (0xfff << 20))));
#pragma mark -
        }
        return MEMTX_OK;
    } else {
#pragma mark DEBUG
        log("hvf_apic_mem_read[%u] hv_vcpu_apic_read(vcpu = %llu, addr = 0x%llx) failed: 0x%x (%s)\n",
            CPU(s->cpu)->cpu_index, vcpu,
            addr, result, hvf_return_string(result));
#pragma mark -
        return MEMTX_ERROR;
    }
}


static void hvf_apic_class_init(ObjectClass *klass, void *data)
{
    APICCommonClass *k = APIC_COMMON_CLASS(klass);
    k->realize = hvf_apic_realize;
    k->unrealize = hvf_apic_unrealize;
    k->reset = hvf_apic_reset;
    k->set_base = hvf_apic_set_base;
    k->set_tpr = hvf_apic_set_tpr;
    k->get_tpr = hvf_apic_get_tpr;
    k->post_load = hvf_apic_post_load;
    k->enable_tpr_reporting = hvf_apic_enable_tpr_reporting;
    k->vapic_base_update = hvf_apic_vapic_base_update;
    k->external_nmi = hvf_apic_external_nmi;
    k->send_msi = hvf_apic_send_msi;
}

static const TypeInfo hvf_apic_info = {
    .name = TYPE_HVF_APIC,
    .parent = TYPE_APIC_COMMON,
    .instance_size = sizeof(APICCommonState),
    .class_init = hvf_apic_class_init,
};

static void hvf_apic_register_types(void)
{
    type_register_static(&hvf_apic_info);
}

type_init(hvf_apic_register_types)
