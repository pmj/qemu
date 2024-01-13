#include "qemu/osdep.h"
#include "qemu/module.h"
#include "hw/intc/ioapic.h"
#include "hw/intc/ioapic_internal.h"
#include "hw/i386/apic_internal.h"
#include "sysemu/hvf.h"
#include "sysemu/hvf_int.h"
#include <Hypervisor/hv.h>
#include <execinfo.h>

#pragma mark DEBUG
#include <os/log.h>
//extern os_log_t hvf_log;
/*
#define LP "" //"{public}"
#define log(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__ ) //os_log(OS_LOG_DEFAULT, fmt, ## __VA_ARGS__)
 */
#define LP "{public}"
#define log(fmt, ...) os_log(OS_LOG_DEFAULT, fmt, ## __VA_ARGS__)
#pragma mark -

#define HVF_IOAPIC_NUM_PINS 32 // struct hv_ioapic_state rtbl array members
#define HVF_IOAPIC_NUM_EXTRA_PINS (HVF_IOAPIC_NUM_PINS - IOAPIC_NUM_PINS)


struct HVFIOAPICState {
    IOAPICCommonState ioapic;
    uint32_t num_interrupts;
    uint32_t ioapic_state_version; // version field of hv_ioapic_state_ext_t
    uint64_t ioredtbl_ext[HVF_IOAPIC_NUM_EXTRA_PINS];
    hv_ioapic_state_ext_t saved_reset_state;
    bool first_reset_done;
};
typedef struct HVFIOAPICState HVFIOAPICState;

OBJECT_DECLARE_SIMPLE_TYPE(HVFIOAPICState, HVF_IOAPIC)


static void hvf_ioapic_set_irq(void *opaque, int irq, int level)
{
    /*
    if (irq == 14)
    {
        void* callstack[128];
        int i, frames = backtrace(callstack, 128);
        char** strs = backtrace_symbols(callstack, frames);
        log("hvf_ioapic_set_irq: %u stack frames\n", frames);
        for (i = 0; i < frames; ++i) {
            log("%s\n", strs[i]);
        }
        free(strs);
        fflush(stdout);
    }
    */

    HVFIOAPICState *s = opaque;
    IOAPICCommonState *common = IOAPIC_COMMON(s);
    hv_return_t irq_set_result;

    //log("hvf_ioapic_set_irq(irq = %u, level = %u)\n", irq, level);

    ioapic_stat_update_irq(common, irq, level);
    if (level) {
        irq_set_result = hv_vm_ioapic_assert_irq(irq);
    } else {
        irq_set_result = hv_vm_ioapic_deassert_irq(irq);
    }
    if (irq_set_result != HV_SUCCESS) {
        log("hvf_ioapic_set_irq irq = %u, level = %u, result -> 0x%x (%s)\n", irq, level, irq_set_result, hvf_return_string(irq_set_result));
    }
}

static uint64_t
hvf_ioapic_mem_read(void *opaque, hwaddr addr, unsigned int size)
{
    HVFIOAPICState *s = opaque;
    uint32_t val = UINT32_MAX;
    hv_return_t result = hv_vm_ioapic_read(s->ioapic.io_memory.addr + addr, &val);
    log("hvf_ioapic_mem_read(addr = 0x%llx, MR addr = 0x%llx, size = %u) -> 0x%x, hv_vm_ioapic_read -> 0x%x\n", addr, s->ioapic.io_memory.addr, size, val, result);
    assert_hvf_ok(result);
    return val;
}

static void
hvf_ioapic_mem_write(void *opaque, hwaddr addr, uint64_t val,
                     unsigned int size)
{
    HVFIOAPICState *s = opaque;
    //log("hvf_ioapic_mem_write(addr = 0x%02llx, MR addr = 0x%llx, size = %u, val = 0x%llx)\n", addr, s->ioapic.io_memory.addr, size, val);
    if (addr == IOAPIC_IOREGSEL)
    {
        s->ioapic.ioregsel = val;
    }
    else if (addr == IOAPIC_IOWIN)
    {
        if (s->ioapic.ioregsel == IOAPIC_REG_ID)
        {
            // Only these bits are writable in IOAPIC_REG_ID
            val &= (IOAPIC_ID_MASK << IOAPIC_ID_SHIFT);
            log("hvf_ioapic_mem_write val = 0x%llx\n", val);
        }
        else if (s->ioapic.ioregsel >= IOAPIC_REG_REDTBL_BASE)
        {
            uint32_t pair[2] = {};
            pair[s->ioapic.ioregsel % 2] = val;
            struct {
                uint8_t vector;
                uint8_t delivery_mode:3;
                uint8_t dest_mode:1;
                uint8_t delivery_status:1;
                uint8_t polarity:1;
                uint8_t remote_irr:1;
                uint8_t trig_mode:1;
                uint8_t mask:1;
                uint8_t reserve:7;
                uint8_t reserved[4];
                uint8_t dest_id;
            } redir;
            memcpy(&redir, pair, sizeof(redir));
            if (s->ioapic.ioregsel % 2 == 0)
            {
                /*
                log("hvf_ioapic_mem_write [0x%02x]: vector = 0x%02x, delivery_mode = %u, dest_mode = %u, delivery_status = %u, polarity = %u, remote_irr = %u, trig_mode = %u, mask = %u, reserve = %u, reserved[0] = 0x%02x\n",
                    (s->ioapic.ioregsel - IOAPIC_REG_REDTBL_BASE) / 2,
                    redir.vector, redir.delivery_mode, redir.dest_mode, redir.delivery_status, redir.polarity, redir.remote_irr, redir.trig_mode, redir.mask, redir.reserve, redir.reserved[0]);
                */
            }
            else
            {
                /*
                log("hvf_ioapic_mem_write [0x%02x]: reserved[1…3] = 0x%02x 0x%02x 0x%02x, dest_id = 0x%02x\n",
                    (s->ioapic.ioregsel - IOAPIC_REG_REDTBL_BASE) / 2,
                    redir.reserved[1], redir.reserved[2], redir.reserved[3], redir.dest_id);
                */
            }
        }
    }
    hv_return_t result = hv_vm_ioapic_write(s->ioapic.io_memory.addr + addr, (uint32_t)val);
    assert_hvf_ok(result);
}

static const MemoryRegionOps ioapic_io_ops = {
    .read = hvf_ioapic_mem_read,
    .write = hvf_ioapic_mem_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, }
};

static void hvf_ioapic_realize(DeviceState *dev, Error **errp)
{
    HVFIOAPICState *hvfs = HVF_IOAPIC(dev);
    IOAPICCommonState *s = &hvfs->ioapic;

    hvfs->saved_reset_state.version = HV_IOAPIC_STATE_EXT_VER;
    hv_return_t save_state_result = hv_vm_ioapic_get_state(&hvfs->saved_reset_state);
    assert_hvf_ok(save_state_result);
    hvfs->first_reset_done = false;
    
    memory_region_init_io(&s->io_memory, OBJECT(dev), &ioapic_io_ops, hvfs, "hvf-ioapic", 0x1000);
    
    s->version = 0x11;
    log("hvf_ioapic_realize: IOAPIC version = 0x%x\n", s->version);

    qdev_init_gpio_in(dev, hvf_ioapic_set_irq, HVF_IOAPIC_NUM_PINS);
}

static void hvf_ioapic_get(IOAPICCommonState *s)
{
    HVFIOAPICState *hvfs = HVF_IOAPIC(s);
    int i;
    hv_ioapic_state_ext_t state = {};
    hv_return_t result = hv_vm_ioapic_get_state(&state);
    assert_hvf_ok(result);
    
    struct hv_ioapic_state *st = &state.state;
    
    hvfs->ioapic_state_version = state.version;
    s->id = st->ioa_id;
    s->ioregsel = st->ioregsel;
    s->irr = st->irr;
    
    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        s->ioredtbl[i] = st->rtbl[i];
    }
    for (i = IOAPIC_NUM_PINS; i < HVF_IOAPIC_NUM_PINS; i++) {
        hvfs->ioredtbl_ext[i - IOAPIC_NUM_PINS] = st->rtbl[i];
    }
}

static void hvf_ioapic_put(IOAPICCommonState *s)
{
    HVFIOAPICState *hvfs = HVF_IOAPIC(s);
    int i;

    hv_ioapic_state_ext_t state = {
        .version = hvfs->ioapic_state_version,
        .state = {
            .ioa_id = s->id,
            .ioregsel = s->ioregsel,
            .irr = s->irr,
        },
    };

    for (i = 0; i < IOAPIC_NUM_PINS; i++) {
        state.state.rtbl[i] = s->ioredtbl[i];
    }
    for (i = IOAPIC_NUM_PINS; i < HVF_IOAPIC_NUM_PINS; i++) {
        state.state.rtbl[i] = hvfs->ioredtbl_ext[i - IOAPIC_NUM_PINS];
    }

    hv_return_t result = hv_vm_ioapic_put_state(&state);
    assert_hvf_ok(result);
}

static void hvf_ioapic_reset(DeviceState *dev)
{
    log("hvf_ioapic_reset\n");
    HVFIOAPICState *s = HVF_IOAPIC(dev);

    ioapic_reset_common(dev);
    
    if (s->first_reset_done)
    {
        hv_return_t result = hv_vm_ioapic_put_state(&s->saved_reset_state);
        assert_hvf_ok(result);
    }
    else
    {
        s->first_reset_done = true;
    }
}

static void hvf_ioapic_class_init(ObjectClass *klass, void *data)
{
    IOAPICCommonClass *k = IOAPIC_COMMON_CLASS(klass);
    DeviceClass *dc = DEVICE_CLASS(klass);

    k->realize   = hvf_ioapic_realize;
    k->pre_save  = hvf_ioapic_get;
    k->post_load = hvf_ioapic_put;
    dc->reset    = hvf_ioapic_reset;
    //device_class_set_props(dc, hvf_ioapic_properties);
}

static const TypeInfo hvf_ioapic_info = {
    .name  = TYPE_HVF_IOAPIC,
    .parent = TYPE_IOAPIC_COMMON,
    .instance_size = sizeof(HVFIOAPICState),
    .class_init = hvf_ioapic_class_init,
};
#warning FIXME: Add extra properties for (de-)serialisation

static void hvf_ioapic_register_types(void)
{
    type_register_static(&hvf_ioapic_info);
}

type_init(hvf_ioapic_register_types)
