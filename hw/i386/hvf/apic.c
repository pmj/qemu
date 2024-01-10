/*
 * macOS Hypervisor.framework in-kernel APIC support
 */

#include "qemu/osdep.h"
#include "qom/object.h"
#include "hw/i386/apic_internal.h"
#include "hw/intc/ioapic.h"
#include "hw/pci/msi.h"
#include "sysemu/hvf.h"
#include "sysemu/hvf_int.h"
#include "sysemu/cpus.h"

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

static const char* hvf_exit_info_string(hv_vm_exitinfo_t exit_info)
{
    switch ((uint32_t)exit_info) {
    case HV_VM_EXITINFO_VMX:              return "HV_VM_EXITINFO_VMX";
    case HV_VM_EXITINFO_INIT_AP:          return "HV_VM_EXITINFO_INIT_AP";
    case HV_VM_EXITINFO_STARTUP_AP:       return "HV_VM_EXITINFO_STARTUP_AP";
    case HV_VM_EXITINFO_IOAPIC_EOI:       return "HV_VM_EXITINFO_IOAPIC_EOI";
    case HV_VM_EXITINFO_INJECT_EXCP:      return "HV_VM_EXITINFO_INJECT_EXCP";
    case HV_VM_EXITINFO_SMI:              return "HV_VM_EXITINFO_SMI";
    case HV_VM_EXITINFO_APIC_ACCESS_READ: return "HV_VM_EXITINFO_APIC_ACCESS_READ";
    case 0:                               return "(none)";
    default:                              return "?unknown hv_vm_exitinfo_t?";
    };
}
#pragma mark -


static hv_vcpuid_t get_vcpuid_count(void)
{
    CPUState *some_cpu;
    hv_vcpuid_t vcpu_id_count = 0;
    cpu_list_lock();
    CPU_FOREACH(some_cpu) {
        if (some_cpu->accel->fd >= vcpu_id_count) {
            vcpu_id_count = some_cpu->accel->fd + 1u;
        }
    }
    cpu_list_unlock();
    return vcpu_id_count;
}

// TODO: clean up
void hvf_apic_follow_up_exit_info(APICCommonState *s, hv_vm_exitinfo_t exit_info)
{
    hv_return_t r;
    hv_vcpuid_t vcpu = CPU(s->cpu)->accel->fd;

    switch (exit_info) {
    case HV_VM_EXITINFO_VMX:
    {
        uint32_t vmx_status = 0;
        r = hv_vcpu_vmx_status(vcpu, &vmx_status);
        log("hvf_apic_follow_up_exit_info: hv_vcpu_vmx_status -> 0x%x (%{public}s), status = 0x%x\n", r, hvf_return_string(r), vmx_status);
        assert_hvf_ok(r);
        assert(vmx_status == 0);
        break;
    }
    case HV_VM_EXITINFO_INIT_AP:
    {
        hv_vcpuid_t vcpu_id_count = get_vcpuid_count();
        assert(vcpu_id_count > 0);
        bool cpus_active[vcpu_id_count];
        memset(cpus_active, 0, sizeof(cpus_active));
        char active_vcpu_str_buf[vcpu_id_count * 2 + 3];
        
        r = hv_vcpu_exit_init_ap(vcpu, cpus_active, vcpu_id_count);
        char* pos = active_vcpu_str_buf;
        for (hv_vcpuid_t i = 0; i < vcpu_id_count; ++i) {
            pos += snprintf(pos, active_vcpu_str_buf + sizeof(active_vcpu_str_buf) - pos, "%c ", cpus_active[i] ? '1' : '0');
        }
        log("hvf_apic_follow_up_exit_info: hv_vcpu_exit_init_ap() -> 0x%x (%{public}s), cpus_active = [ %{public}s]\n",
            r, hvf_return_string(r), active_vcpu_str_buf);
        
        
        CPUState *cpus_to_kick[vcpu_id_count];
        uint32_t num_cpus_to_kick = 0;
        CPUState *some_cpu;
        cpu_list_lock();
        CPU_FOREACH(some_cpu) {
            if (cpus_active[some_cpu->accel->fd]) {
                cpus_to_kick[num_cpus_to_kick] = some_cpu;
                ++num_cpus_to_kick;
            }
        }
        cpu_list_unlock();
        
        for (uint32_t i = 0; i < num_cpus_to_kick; ++i)
        {
            CPUState *cpu = cpus_to_kick[i];
            X86CPU *x86cpu = X86_CPU(cpu);
            APICCommonState *apic = APIC_COMMON(x86cpu->apic_state);
            if (!apic->wait_for_sipi) {
                // Re-init of already-started CPU, send interrupt
                log("hvf_apic_follow_up_exit_info: Sending INIT interrupt to CPU %u\n", cpu->cpu_index);
                cpu_interrupt(cpu, CPU_INTERRUPT_INIT);
                /*r = hv_vm_lapic_set_intr(cpu->accel->fd, 0, HV_APIC_EDGE_TRIGGER);
                assert_hvf_ok(r);*/
            } else {
                log("hvf_apic_follow_up_exit_info: CPU %u: no INIT interrupt on first AP INIT\n", cpu->cpu_index);
            }
        }
        break;
    }
    case HV_VM_EXITINFO_STARTUP_AP:
    {
        hv_vcpuid_t vcpu_id_count = get_vcpuid_count();
        assert(vcpu_id_count > 0);
        bool cpus_active[vcpu_id_count];
        memset(cpus_active, 0, sizeof(cpus_active));
        char active_vcpu_str_buf[vcpu_id_count * 2 + 3];
        
        uint64_t ap_rip = 0;
        r = hv_vcpu_exit_startup_ap(vcpu, cpus_active, vcpu_id_count, &ap_rip);
        char* pos = active_vcpu_str_buf;
        for (hv_vcpuid_t i = 0; i < vcpu_id_count; ++i) {
            pos += snprintf(pos, active_vcpu_str_buf + sizeof(active_vcpu_str_buf) - pos, "%c ", cpus_active[i] ? '1' : '0');
        }
        log("hvf_apic_follow_up_exit_info: hv_vcpu_exit_startup_ap() -> 0x%x (%{public}s), cpus_active = [ %{public}s], ap_rip = 0x%llx\n",
            r, hvf_return_string(r), active_vcpu_str_buf, ap_rip);
        
        /*
        hv_atpic_state_ext_t atpic_state = { .version = HV_ATPIC_STATE_EXT_VER };
        r = hv_vm_atpic_get_state(&atpic_state, true);
        */
        
        CPUState *cpus_to_kick[vcpu_id_count];
        uint32_t num_cpus_to_kick = 0;
        CPUState *some_cpu;
        cpu_list_lock();
        CPU_FOREACH(some_cpu) {
            if (cpus_active[some_cpu->accel->fd]) {
                cpus_to_kick[num_cpus_to_kick] = some_cpu;
                ++num_cpus_to_kick;
            }
        }
        cpu_list_unlock();
        
        for (uint32_t i = 0; i < num_cpus_to_kick; ++i)
        {
            CPUState *cpu = cpus_to_kick[i];
            X86CPU *x86cpu = X86_CPU(cpu);
            APICCommonState *apic = APIC_COMMON(x86cpu->apic_state);
            if (apic->wait_for_sipi)
            {
                apic->sipi_vector = (ap_rip >> 12u);
                log("hvf_apic_follow_up_exit_info: waking CPU %u\n", cpu->cpu_index);
                
                // TODO: FIXME
                bool was_halted = cpus_to_kick[i]->halted;
                if (was_halted)
                {
                    log("hvf_apic_follow_up_exit_info: CPU [%u] halted = %u\n", cpu->cpu_index, cpu->halted);
                    //apic->wait_for_sipi = false;
                    cpu->halted = 0;
                    /*macvm_set_rip(cpu, ap_rip);
                    
                    cpu_x86_load_seg_cache_sipi(x86cpu, apic->sipi_vector);
                    */
                }
                //else
                {
                    log("hvf_apic_follow_up_exit_info: CPU %u not halted, sending interrupt\n", cpu->cpu_index);
                    cpu_interrupt(cpus_to_kick[i], CPU_INTERRUPT_SIPI);
                }

                if (was_halted)
                    qemu_cond_broadcast(cpu->halt_cond);

                //qemu_cpu_kick(cpus_to_kick[i]);
            } else {
                log("hvf_apic_follow_up_exit_info: CPU %u handling SIPI but not in wait_for_sipi state?\n", cpu->cpu_index);
            }
        }
        break;
    }
    case HV_VM_EXITINFO_IOAPIC_EOI:
    {
        uint8_t vec = 0;
        hv_return_t res = hv_vcpu_exit_ioapic_eoi(vcpu, &vec);
        
        log("hvf_apic_follow_up_exit_info: exit_info = HV_VM_EXITINFO_IOAPIC_EOI, hv_vcpu_exit_ioapic_eoi -> 0x%x, vector = 0x%x\n", res, vec);
        ioapic_eoi_broadcast(vec);

        break;
    }
    case HV_VM_EXITINFO_APIC_ACCESS_READ:
    {
        // (I think this is after vCPU run only)
        uint32_t apic_reg = UINT32_MAX;
        hv_return_t res = hv_vcpu_exit_apic_access_read(vcpu, &apic_reg);
        log("hvf_apic_follow_up_exit_info: exit_info = HV_VM_EXITINFO_APIC_ACCESS_READ, value = 0x%x (hv_vcpu_exit_apic_access_read -> 0x%x %{public}s)\n", apic_reg, res, hvf_return_string(res));
        exit(1);
        break;
    }
    case HV_VM_EXITINFO_INJECT_EXCP:
        log("hvf_apic_follow_up_exit_info: exit_info = HV_VM_EXITINFO_INJECT_EXCP\n");
        // (I think this is after vCPU run only)
        // hv_return_t hv_vcpu_exit_inject_excp(hv_vcpuid_t vcpu,
        // uint8_t *vec, bool *valid, uint32_t *code, bool *restart)
        exit(1);
        break;
    
    case HV_VM_EXITINFO_SMI:
        log("hvf_apic_follow_up_exit_info: exit_info = HV_VM_EXITINFO_SMI\n");
        exit(1);
        break;
        
    default:
        {
            log("hvf_apic_follow_up_exit_info: WARNING: UNEXPECTED exit_info = %u\n", exit_info);
        }
    }

}


static void hvf_apic_send_msi(MSIMessage *msg)
{
    /* hv_vm_lapic_msi() wants the full GPA, not just the offset */
    uint64_t msi_address = msg->address | 0xfee00000;
    assert_hvf_ok(hv_vm_lapic_msi(msi_address, msg->data));
}

static MemTxResult hvf_apic_mem_read(void *opaque, hwaddr addr, uint64_t *data,
                                     unsigned size, MemTxAttrs attrs)
{
    hvf_vcpuid vcpu;
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
        log("hvf_apic_mem_read[%u] hv_vcpu_apic_read(vcpu = %u, addr = 0x%llx) failed: 0x%x (%s)\n",
            CPU(s->cpu)->cpu_index, vcpu,
            addr, result, hvf_return_string(result));
#pragma mark -
        return MEMTX_ERROR;
    }
}

static void hvf_apic_mem_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    hv_vcpuid_t vcpu;
    APICCommonState *s;
    CPUState *cpu;
    DeviceState *dev;
    bool no_side_effect = false;
    
    if (addr > 0xfff || addr == 0) {
        /* MSI and MMIO APIC are at the same memory location,
         * but actually not on the global bus: MSI is on PCI bus
         * APIC is connected directly to the CPU.
         * Mapping them on the global bus happens to work because
         * MSI registers are reserved in APIC MMIO and vice versa. */
        MSIMessage msi = { .address = addr, .data = data };
        hvf_apic_send_msi(&msi);
        return;
    }

    dev = cpu_get_current_apic();
    if (dev == NULL) {
#pragma mark DEBUG
        fprintf(stderr, "hvf_apic_mem_write: WARNING! No current APIC found, ignoring %u byte write of 0x%llx at 0x%llx\n",
            size, data, addr);
        log("hvf_apic_mem_write: WARNING! No current APIC found, ignoring %u byte write of 0x%llx at 0x%llx\n",
            size, data, addr);
#pragma mark -
        return;
    }
    s = APIC_COMMON(dev);
    
    cpu = CPU(s->cpu);
    
#pragma mark DEBUG
    if (cpu->cpu_index != 0)
    {
        log("hvf_apic_mem_write apic = { id = 0x%x } addr = 0x%llx, data = 0x%llx, size = %u [APIC disabled, ignoring writes]\n", s->id, addr, data, size);
    }
#pragma mark -
    
    assert(qemu_in_vcpu_thread());
    
    if (!(s->apicbase & MSR_IA32_APICBASE_ENABLE)) {
#pragma mark DEBUG
        static bool has_logged = false;
        if (!has_logged) {
            log("hvf_apic_mem_write apic = { id = 0x%x } addr = 0x%llx, data = 0x%llx, size = %u [APIC disabled, ignoring writes]\n", s->id, addr, data, size);
            has_logged = true;
        }
#pragma mark -
        return;
    }
    if (size != 4)
    {
#pragma mark DEBUG
        log("hvf_apic_mem_write[%u] apic = { id = 0x%x } addr = 0x%llx, data = 0x%llx, size = %u\n", //; qemu_in_vcpu_thread() -> %s\n",
            s->initial_apic_id, s->id, addr, data, size/*, vcpu_thread ? "true" : "false"*/);
        log("hvf_apic_mem_write: Warning! %u-byte write to offset 0x%llx, expecting only 4-byte writes\n", size, addr);
#pragma mark -
        // TODO: report error
    }

    vcpu = cpu->accel->fd;

#pragma mark DEBUG
    bool skip_log = (addr == 0xb0);

    if (addr == 0x300 && ((data >> 8) & 0x7) >= 5)
    {
        log("hvf_apic_mem_write_job[cpu %u]: %{public}s to %{public}s destination\n", //; APIC state before write:\n",
            cpu->cpu_index,
            apic_dest_mode_str(((data >> 8) & 0x7)), apic_dest_type_str((data >> 18) & 0x3));
        //hvf_dump_kernel_apic_state(apic);
    }
#pragma mark -
    
    hv_return_t result = hv_vcpu_apic_write(
        vcpu, addr, data, &no_side_effect);

#pragma mark DEBUG
    if (!skip_log || result != HV_SUCCESS)
        log("hvf_apic_mem_write_job hv_vcpu_apic_write[%u](addr = 0x%llx, data = 0x%llx) -> 0x%x (%{public}s) no_side_effect = %{public}s\n",
            cpu->cpu_index, addr, data, result, hvf_return_string(result), no_side_effect ? "true" : "false");
 
    if (addr == 0x300) {
        uint32_t d = data;
        log("hvf_apic_mem_write_job[%u] ICR write: vector: 0x%02x, mode: %u (%{public}s), dest mode: %u, status: %u, init level deassert 0: %u, init level deassert 1: %u, destination type: %u (%{public}s), reserved: 0x%x\n",
            cpu->cpu_index,
            d & 0xff,
            (d >> 8) & 0x7, apic_dest_mode_str((d >> 8) & 0x7),
            (d >> 11) & 0x1,
            (d >> 12) & 0x1,
            (d >> 14) & 0x1,
            (d >> 15) & 0x1,
            (d >> 18) & 0x3, apic_dest_type_str((d >> 18) & 0x3),
            (d & ((1u << 13) | (3u << 16) | (0xfff << 20))));
    }
#pragma mark -
    
    if (!no_side_effect) {
        hv_vm_exitinfo_t exit_info = 0;
        result = hv_vcpu_exit_info(vcpu, &exit_info);
#pragma mark DEBUG
        log("hvf_apic_mem_write_job hv_vcpu_exit_info -> exit info: %u (%{public}s), result: 0x%x (%{public}s)\n", exit_info, hvf_exit_info_string(exit_info), result, hvf_return_string(result));
#pragma mark -
        hvf_apic_follow_up_exit_info(s, exit_info);
    }

#pragma mark DEBUG
    if (addr == 0x300 && ((data >> 8) & 0x7) >= 5)
    {
        log("hvf_apic_mem_write: %{public}s to %{public}s destination; APIC state after write:\n", apic_dest_mode_str(((data >> 8) & 0x7)), apic_dest_type_str((data >> 18) & 0x3));
        //hvf_dump_kernel_apic_state(apic);
    }
    
    if (addr == 0xb0 && no_side_effect) {
        uint8_t vec = 0;
        result = hv_vcpu_exit_ioapic_eoi(vcpu, &vec);
        log("hvf_apic_mem_write: No side effect, but write to EOI register? hv_vcpu_exit_ioapic_eoi -> result 0x%x (%s) vector 0x%x\n", result, hvf_return_string(result), vec);
        if (result == HV_SUCCESS)
        {
            ioapic_eoi_broadcast(vec);
        } else {
            //log("hv_vcpu_exit_ioapic_eoi -> 0x%x (%s), vector = 0x%x\n", result, hvf_return_string(result), vec);
        }
    }
}


static const MemoryRegionOps hvf_apic_io_ops = {
    .read_with_attrs =  hvf_apic_mem_read,
    .write = hvf_apic_mem_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4, }
};

static void hvf_apic_realize(DeviceState *dev, Error **errp)
{
    APICCommonState *s = APIC_COMMON(dev);
    memory_region_init_io(&s->io_memory, OBJECT(s), &hvf_apic_io_ops, s,
                          "hvf-apic-msi", 0x1000);
    msi_nonbroken = true;
}

static void hvf_apic_set_base(APICCommonState *s, uint64_t val)
+{
+    uint32_t new_base_addr, old_base_addr;
+    uint32_t new_flags, old_flags;
+
+    new_base_addr = val & MSR_IA32_APICBASE_BASE;
+    old_base_addr = s->apicbase & MSR_IA32_APICBASE_BASE;
+    
+    new_flags = val & MSR_IA32_APICBASE_FLAGS_MASK;
+    old_flags = s->apicbase & MSR_IA32_APICBASE_FLAGS_MASK;
+
+    log("hvf_apic_set_base: s = %p { id = %u, arb_id = %u}, val = 0x%llx, flags: 0x%x -> 0x%x\n",
+        s, s->id, s->arb_id, val, old_flags, new_flags);
+
+    //hvf_dump_kernel_apic_state(s);
+    
+    assert(qemu_mutex_iothread_locked());
+
+    // The only valid pattern of change (other than no change) in the flags is:
+    // (old_flags -> new_flags)
+    // 0 -> ENABLE
+    // ENABLE -> 0
+    // ENABLE -> ENABLE | EXTD
+    // ENABLE | EXTD -> 0
+    // Additionally, the base address must fit in 32 bits, and the low bits of the register are reserved
+    if (!(new_flags == 0                  // transition to 0 (disable) is always allowed
+          || new_flags == old_flags
+          || (old_flags == 0 && new_flags == MSR_IA32_APICBASE_ENABLE)
+          || (old_flags == MSR_IA32_APICBASE_ENABLE && new_flags == MSR_IA32_APICBASE_FLAGS_X2APIC_ENABLED))
+        || val > UINT32_MAX
+        || 0 != (val & MSR_IA32_APICBASE_RESERVED_MASK)) {
+        log("hvf_apic_set_base: setting bad APICBASE flags or value (0x%x -> 0x%x, val = 0x%llx)\n", old_flags, new_flags, val);
+        
+        CPUX86State *env = &X86_CPU(s->cpu)->env;
+        
+        env->exception_nr = EXCP0D_GPF;
+        env->exception_injected = 1;
+        env->has_error_code = true;
+        env->error_code = 0;
+
+        return;
+    }
+
+    bool enabling, disabling, mmio_enabled, mmio_was_enabled, moving_mmio;
+
+    moving_mmio = new_base_addr != old_base_addr;
+    
+    if ((val & MSR_IA32_APICBASE_ENABLE) != (s->apicbase & MSR_IA32_APICBASE_ENABLE)) {
+        disabling = !(val & MSR_IA32_APICBASE_ENABLE);
+        enabling = !disabling;
+    } else {
+        enabling = disabling = false;
+    }
+    
+    // MMIO is enabled if APIC is enabled but NOT x2apic
+    mmio_enabled = (new_flags == MSR_IA32_APICBASE_ENABLE);
+    mmio_was_enabled = (old_flags == MSR_IA32_APICBASE_ENABLE);
+    
+    //hv_vcpuid_t vcpu = CPU(s->cpu)->hvf->fd;
+    log("hvf_apic_set_base: enabling = %s, disabling = %s, moving_mmio = %s, new_base_addr = 0x%x, old_base_addr = 0x%x\n",
+        enabling ? "yes" : "no", disabling ? "yes" : "no", moving_mmio ? "yes" : "no",
+        new_base_addr, old_base_addr);
+ 
+    s->apicbase =
+        new_base_addr |
+        new_flags |
+        (s->apicbase & MSR_IA32_APICBASE_BSP);
+    
+    if (/*mmio_enabled != mmio_was_enabled ||*/ moving_mmio) {
+        hv_vcpuid_t vcpu = CPU(s->cpu)->hvf->fd;
+        /*if (!mmio_enabled || (mmio_was_enabled && moving_mmio)) {*/
+            log("hvf_apic_set_base: disabling APIC mmio\n");
+            memory_region_del_subregion(get_system_memory(), &s->io_memory);
+        /*    if (!mmio_enabled) {
+                hv_return_t result = hv_vmx_vcpu_set_apic_address(vcpu, 0);
+                assert_hvf_ok(result);
+            }
+        }
+        
+        if (mmio_enabled) {*/
+            log("hvf_apic_set_base: enabling APIC mmio at 0x%x\n", new_base_addr);
+            hv_return_t result = hv_vmx_vcpu_set_apic_address(vcpu, new_base_addr);
+            assert_hvf_ok(result);
+            memory_region_add_subregion_overlap(get_system_memory(),
+                                                new_base_addr,
+                                                &s->io_memory,
+                                                0x1000);
+       // }
+    }
+    
+    if (disabling) {
+        s->apicbase &= ~MSR_IA32_APICBASE_ENABLE;
+        cpu_clear_apic_feature(&s->cpu->env);
+        s->spurious_vec &= ~APIC_SV_ENABLE;
+    }
+
+    if (enabling) {
+        s->apicbase |= MSR_IA32_APICBASE_ENABLE;
+        s->cpu->env.features[FEAT_1_EDX] |= CPUID_APIC;
+        s->spurious_vec |= APIC_SV_ENABLE;
+    }
+
+
+}


static void hvf_apic_reset(APICCommonState *s)
{
    log("hvf_apic_reset[%u]\n", CPU(s->cpu)->cpu_index);
}

static void hvf_apic_class_init(ObjectClass *klass, void *data)
{
    APICCommonClass *k = APIC_COMMON_CLASS(klass);
    k->realize = hvf_apic_realize;
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
