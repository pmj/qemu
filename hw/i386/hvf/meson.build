i386_hvf_ss = ss.source_set()
i386_hvf_ss.add(when: 'CONFIG_APIC', if_true: files('apic.c'))

i386_ss.add_all(when: 'CONFIG_HVF', if_true: i386_hvf_ss)
