/*
 * QEMU Apple ParavirtualizedGraphics.framework device
 *
 * Copyright © 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * ParavirtualizedGraphics.framework is a set of libraries that macOS provides
 * which implements 3d graphics passthrough to the host as well as a
 * proprietary guest communication channel to drive it. This device model
 * implements support to drive that library from within QEMU.
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "trace.h"
#include "hw/sysbus.h"
#include "hw/pci/msi.h"
#include "crypto/hash.h"
#include "sysemu/cpus.h"
#include "ui/console.h"
#include "monitor/monitor.h"
#include <mach/mach_vm.h>
#import <ParavirtualizedGraphics/ParavirtualizedGraphics.h>

#define TYPE_APPLE_GFX          "apple-gfx"

static const PGDisplayCoord_t apple_gfx_modes[] = {
    { .x = 1440, .y = 1080 },
    { .x = 1280, .y = 1024 },
};

static dispatch_queue_t pg_task_q = NULL;

static void print_queue_labels()
{
	dispatch_queue_global_t dq = dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0);
	fprintf(stderr, "pg_task_q: '%s' (%p), current: '%s' (%p), default: '%s' (%p)\n", dispatch_queue_get_label(pg_task_q), pg_task_q, dispatch_queue_get_label(DISPATCH_CURRENT_QUEUE_LABEL), dispatch_get_current_queue(), dispatch_queue_get_label(dq), dq);
}

#define assert_thread_safety() ({ if (pg_task_q) { if (pg_task_q != dispatch_get_current_queue()) { print_queue_labels(); } } else { pg_task_q = dispatch_get_current_queue(); } })

/*
 * ParavirtualizedGraphics.Framework only ships header files for the x86
 * variant which does not include IOSFC descriptors and host devices. We add
 * their definitions here so that we can also work with the ARM version.
 */
typedef bool(^IOSFCRaiseInterrupt)(uint32_t vector);
typedef bool(^IOSFCUnmapMemory)(void *a, void *b, void *c, void *d, void *e, void *f);
typedef bool(^IOSFCMapMemory)(uint64_t phys, uint64_t len, bool ro, void **va, void *e, void *f);

@interface PGDeviceDescriptorExt : PGDeviceDescriptor
@property (readwrite, nonatomic) bool usingIOSurfaceMapper;
@end

@interface PGIOSurfaceHostDeviceDescriptor : NSObject
-(PGIOSurfaceHostDeviceDescriptor *)init;
@property (readwrite, nonatomic, copy, nullable) IOSFCMapMemory mapMemory;
@property (readwrite, nonatomic, copy, nullable) IOSFCUnmapMemory unmapMemory;
@property (readwrite, nonatomic, copy, nullable) IOSFCRaiseInterrupt raiseInterrupt;
@end

@interface PGIOSurfaceHostDevice : NSObject
-(void)initWithDescriptor:(PGIOSurfaceHostDeviceDescriptor *) desc;
-(uint32_t)mmioReadAtOffset:(size_t) offset;
-(void)mmioWriteAtOffset:(size_t) offset value:(uint32_t)value;
@end

typedef struct AppleGFXTask {
    QTAILQ_ENTRY(AppleGFXTask) node;
    mach_vm_address_t address;
    uint64_t len;
} AppleGFXTask;

typedef QTAILQ_HEAD(, AppleGFXTask) AppleGFXTaskList;

typedef struct AppleGFXState {
    /* Private */
    SysBusDevice parent_obj;

    /* Public */
    qemu_irq irq_gfx;
    qemu_irq irq_iosfc;
    MemoryRegion iomem_gfx;
    MemoryRegion iomem_iosfc;
    id<PGDevice> pgdev;
    id<PGDisplay> pgdisp;
    PGIOSurfaceHostDevice *pgiosfc;
    AppleGFXTaskList tasks;
    QemuConsole *con;
    void *vram;
    id<MTLDevice> mtl;
    id<MTLTexture> texture;
    bool handles_frames;
    bool new_frame;
    bool cursor_show;
    DisplaySurface *surface;
    QEMUCursor *cursor;
} AppleGFXState;


OBJECT_DECLARE_SIMPLE_TYPE(AppleGFXState, APPLE_GFX)

static AppleGFXTask *apple_gfx_new_task(AppleGFXState *s, uint64_t len)
{
    assert_thread_safety();
    mach_vm_address_t task_mem;
    AppleGFXTask *task;
    kern_return_t r;

    r = mach_vm_allocate(mach_task_self(), &task_mem, len, VM_FLAGS_ANYWHERE);
    if (r != KERN_SUCCESS || task_mem == 0) {
        return NULL;
    }

    task = g_new0(AppleGFXTask, 1);
    
    task->address = task_mem;
    task->len = len;
    QTAILQ_INSERT_TAIL(&s->tasks, task, node);

    return task;
}

static uint64_t apple_gfx_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleGFXState *s = opaque;
    uint64_t res = 0;

    res = [s->pgdev mmioReadAtOffset:offset];

    trace_apple_gfx_read(offset, res);

    return res;
}

static void apple_gfx_write(void *opaque, hwaddr offset, uint64_t val, unsigned size)
{
    AppleGFXState *s = opaque;

    trace_apple_gfx_write(offset, val);

    qemu_mutex_unlock_iothread();
    [s->pgdev mmioWriteAtOffset:offset value:val];
    qemu_mutex_lock_iothread();
}

static const MemoryRegionOps apple_gfx_ops = {
    .read = apple_gfx_read,
    .write = apple_gfx_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t apple_iosfc_read(void *opaque, hwaddr offset, unsigned size)
{
    AppleGFXState *s = opaque;
    uint64_t res = 0;

    qemu_mutex_unlock_iothread();
    res = [s->pgiosfc mmioReadAtOffset:offset];
    qemu_mutex_lock_iothread();

    trace_apple_iosfc_read(offset, res);

    return res;
}

static void apple_iosfc_write(void *opaque, hwaddr offset, uint64_t val, unsigned size)
{
    AppleGFXState *s = opaque;

    trace_apple_iosfc_write(offset, val);

    [s->pgiosfc mmioWriteAtOffset:offset value:val];
}

static const MemoryRegionOps apple_iosfc_ops = {
    .read = apple_iosfc_read,
    .write = apple_iosfc_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
};

static void apple_gfx_fb_update_display(void *opaque)
{
    assert(qemu_mutex_iothread_locked());
    AppleGFXState *s = opaque;

    if (!s->new_frame || !s->handles_frames) {
        return;
    }

    s->new_frame = false;

    BOOL r;
    uint32_t width = surface_width(s->surface);
    uint32_t height = surface_height(s->surface);
    MTLRegion region = MTLRegionMake2D(0, 0, width, height);
    id<MTLCommandQueue> commandQueue = [s->mtl newCommandQueue];
    id<MTLCommandBuffer> mipmapCommandBuffer = [commandQueue commandBuffer];

    r = [s->pgdisp encodeCurrentFrameToCommandBuffer:mipmapCommandBuffer
                                             texture:s->texture
                                              region:region];

    if (r != YES) {
        return;
    }

    id<MTLBlitCommandEncoder> blitCommandEncoder = [mipmapCommandBuffer blitCommandEncoder];
    [blitCommandEncoder endEncoding];
    [mipmapCommandBuffer commit];
    [mipmapCommandBuffer waitUntilCompleted];
    [s->texture getBytes:s->vram bytesPerRow:(width * 4)
                                 bytesPerImage: (width * height * 4)
                                 fromRegion: region
                                 mipmapLevel: 0
                                 slice: 0];

    /* Need to render cursor manually if not supported by backend */
    if (!dpy_cursor_define_supported(s->con) && s->cursor && s->cursor_show) {
        pixman_image_t *image =
            pixman_image_create_bits(PIXMAN_a8r8g8b8,
                                     s->cursor->width,
                                     s->cursor->height,
                                     (uint32_t *)s->cursor->data,
                                     s->cursor->width * 4);

        pixman_image_composite(PIXMAN_OP_OVER,
                               image, NULL, s->surface->image,
                               0, 0, 0, 0, s->pgdisp.cursorPosition.x,
                               s->pgdisp.cursorPosition.y, s->cursor->width,
                               s->cursor->height);

        pixman_image_unref(image);
    }

    dpy_gfx_update_full(s->con);

    [commandQueue release];
}

static const GraphicHwOps apple_gfx_fb_ops = {
    .gfx_update = apple_gfx_fb_update_display,
};

static void update_cursor(AppleGFXState *s)
{
    //assert(qemu_mutex_iothread_locked());
    dpy_mouse_set(s->con, s->pgdisp.cursorPosition.x, s->pgdisp.cursorPosition.y, s->cursor_show);

    /* Need to render manually if cursor is not natively supported */
    if (!dpy_cursor_define_supported(s->con)) {
        s->new_frame = true;
    }
}

static void set_mode(AppleGFXState *s, uint32_t width, uint32_t height)
{
    void *vram = NULL;
    void *old_vram = s->vram;
    DisplaySurface *surface;
    MTLTextureDescriptor *textureDescriptor;
    id<MTLTexture> old_texture = nil;
    id<MTLTexture> texture = nil;

    qemu_mutex_lock_iothread();
    if (s->surface &&
        width == surface_width(s->surface) &&
        height == surface_height(s->surface)) {
        qemu_mutex_unlock_iothread();
        return;
    }
    qemu_mutex_unlock_iothread();

    vram = g_malloc0(width * height * 4);
    surface = qemu_create_displaysurface_from(width, height, PIXMAN_LE_a8r8g8b8,
                                              width * 4, vram);
    
    @autoreleasepool {
        textureDescriptor = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatBGRA8Unorm
                                         width:width
                                        height:height
                                     mipmapped:NO];
        textureDescriptor.usage = s->pgdisp.minimumTextureUsage;
        texture = [s->mtl newTextureWithDescriptor:textureDescriptor];
    }
    
    qemu_mutex_lock_iothread();
    old_vram = s->vram;
    s->vram = vram;
    s->surface = surface;
    dpy_gfx_replace_surface(s->con, surface);
    old_texture = s->texture;
    s->texture = texture;
    qemu_mutex_unlock_iothread();
    
    g_free(old_vram);
    [old_texture release];
}

static void create_fb(AppleGFXState *s)
{

    s->con = graphic_console_init(NULL, 0, &apple_gfx_fb_ops, s);
    set_mode(s, 1440, 1080);

    s->cursor_show = true;
}

static void apple_gfx_reset(DeviceState *d)
{
}

static void apple_gfx_init(Object *obj)
{
    AppleGFXState *s = APPLE_GFX(obj);

    memory_region_init_io(&s->iomem_gfx, obj, &apple_gfx_ops, s, TYPE_APPLE_GFX, 0x4000);
    memory_region_init_io(&s->iomem_iosfc, obj, &apple_iosfc_ops, s, TYPE_APPLE_GFX, 0x10000);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem_gfx);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->iomem_iosfc);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq_gfx);
    sysbus_init_irq(SYS_BUS_DEVICE(s), &s->irq_iosfc);
}

static void apple_gfx_realize(DeviceState *dev, Error **errp)
{
    AppleGFXState *s = APPLE_GFX(dev);
    PGDeviceDescriptor *desc = [PGDeviceDescriptor new];
    PGDisplayDescriptor *disp_desc = [PGDisplayDescriptor new];
    PGIOSurfaceHostDeviceDescriptor *iosfc_desc = [PGIOSurfaceHostDeviceDescriptor new];
    PGDeviceDescriptorExt *desc_ext = (PGDeviceDescriptorExt *)desc;
    PGDisplayMode *modes[ARRAY_SIZE(apple_gfx_modes)];
    int i;

    for (i = 0; i < ARRAY_SIZE(apple_gfx_modes); i++) {
        modes[i] = [PGDisplayMode new];
        [modes[i] initWithSizeInPixels:apple_gfx_modes[i] refreshRateInHz:60.];
    }

    s->mtl = MTLCreateSystemDefaultDevice();

    desc.device = s->mtl;
    desc_ext.usingIOSurfaceMapper = true;

    desc.createTask = ^(uint64_t vmSize, void * _Nullable * _Nonnull baseAddress) {
        AppleGFXTask *task = apple_gfx_new_task(s, vmSize);
        *baseAddress = (void*)task->address;
        trace_apple_gfx_create_task(vmSize, *baseAddress);
        return (PGTask_t *)task;
    };

    desc.destroyTask = ^(PGTask_t * _Nonnull _task) {
				assert_thread_safety();
        AppleGFXTask *task = (AppleGFXTask *)_task;
        trace_apple_gfx_destroy_task(task);
        QTAILQ_REMOVE(&s->tasks, task, node);
        mach_vm_deallocate(mach_task_self(), task->address, task->len);
        g_free(task);
    };

    desc.mapMemory = ^(PGTask_t * _Nonnull _task, uint32_t rangeCount, uint64_t virtualOffset, bool readOnly, PGPhysicalMemoryRange_t * _Nonnull ranges) {
        AppleGFXTask *task = (AppleGFXTask*)_task;
        kern_return_t r;
        mach_vm_address_t target, source;
        trace_apple_gfx_map_memory(task, rangeCount, virtualOffset, readOnly);
        for (int i = 0; i < rangeCount; i++) {
            PGPhysicalMemoryRange_t *range = &ranges[i];
            MemoryRegion *tmp_mr;
            /* TODO: Bounds checks? r/o? */
            qemu_mutex_lock_iothread();

            trace_apple_gfx_map_memory_range(i, range->physicalAddress, range->physicalLength, NULL);

            target = task->address + virtualOffset;
            source = (mach_vm_address_t)gpa2hva(&tmp_mr,
                                                range->physicalAddress,
                                                range->physicalLength, NULL);
            vm_prot_t cur_protection = 0;
            vm_prot_t max_protection = 0;
            // Map guest RAM at range->physicalAddress into PG task memory range
            r = mach_vm_remap(mach_task_self(),
                              &target, range->physicalLength, vm_page_size - 1,
                              VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                              mach_task_self(),
                              source, false /* shared mapping, no copy */,
                              &cur_protection, &max_protection,
                              VM_INHERIT_COPY);
            trace_apple_gfx_remap(r, source, target);
            g_assert(r == KERN_SUCCESS);

            qemu_mutex_unlock_iothread();

            virtualOffset += range->physicalLength;
        }
        return (bool)true;
    };

    desc.unmapMemory = ^(PGTask_t * _Nonnull _task, uint64_t virtualOffset, uint64_t length) {
			assert_thread_safety();
        AppleGFXTask *task = (AppleGFXTask *)_task;
        kern_return_t r;
        mach_vm_address_t range_address;

        trace_apple_gfx_unmap_memory(task, virtualOffset, length);
        
        // Replace task memory range with fresh pages, undoing the mapping from guest RAM
        range_address = task->address + virtualOffset;
        r = mach_vm_allocate(mach_task_self(), &range_address, length,
                             VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
        g_assert(r == KERN_SUCCESS);
        
        return (bool)true;
    };

    desc.readMemory = ^(uint64_t physicalAddress, uint64_t length, void * _Nonnull dst) {
        trace_apple_gfx_read_memory(physicalAddress, length, dst);
        cpu_physical_memory_read(physicalAddress, dst, length);
        return (bool)true;
    };

    desc.raiseInterrupt = ^(uint32_t vector) {
        bool locked;

        trace_apple_gfx_raise_irq(vector);
        locked = qemu_mutex_iothread_locked();
        if (!locked) {
            qemu_mutex_lock_iothread();
        }
        qemu_irq_pulse(s->irq_gfx);
        if (!locked) {
            qemu_mutex_unlock_iothread();
        }
    };

    s->pgdev = PGNewDeviceWithDescriptor(desc);

    disp_desc.name = @"QEMU display";
    disp_desc.sizeInMillimeters = NSMakeSize(400., 300.); /* A 20" display */
    disp_desc.queue = dispatch_get_main_queue();
    disp_desc.newFrameEventHandler = ^(void) {
        trace_apple_gfx_new_frame();

        /* Tell QEMU gfx stack that a new frame arrived */
        s->handles_frames = true;
        s->new_frame = true;
    };
    disp_desc.modeChangeHandler = ^(PGDisplayCoord_t sizeInPixels, OSType pixelFormat) {
        trace_apple_gfx_mode_change(sizeInPixels.x, sizeInPixels.y);
        set_mode(s, sizeInPixels.x, sizeInPixels.y);
    };
    disp_desc.cursorGlyphHandler = ^(NSBitmapImageRep *glyph, PGDisplayCoord_t hotSpot) {
        uint32_t bpp = glyph.bitsPerPixel;
        uint64_t width = glyph.pixelsWide;
        uint64_t height = glyph.pixelsHigh;

        trace_apple_gfx_cursor_set(bpp, width, height);

        if (s->cursor) {
            cursor_unref(s->cursor);
        }
        s->cursor = cursor_alloc(width, height);

        /* TODO handle different bpp */
        if (bpp == 32) {
            memcpy(s->cursor->data, glyph.bitmapData, glyph.bytesPerPlane);
            dpy_cursor_define(s->con, s->cursor);
            update_cursor(s);
        }
    };
    disp_desc.cursorShowHandler = ^(BOOL show) {
        trace_apple_gfx_cursor_show(show);
        s->cursor_show = show;
        update_cursor(s);
    };
    
    disp_desc.cursorMoveHandler = ^(void) {
        trace_apple_gfx_cursor_move();
        update_cursor(s);
    };

    s->pgdisp = [s->pgdev newDisplayWithDescriptor:disp_desc port:0 serialNum:1234];
    s->pgdisp.modeList = [NSArray arrayWithObjects:modes count:ARRAY_SIZE(apple_gfx_modes)];

    [iosfc_desc init];
    iosfc_desc.mapMemory = ^(uint64_t phys, uint64_t len, bool ro, void **va, void *e, void *f) {
        trace_apple_iosfc_map_memory(phys, len, ro, va, e, f);
        MemoryRegion *tmp_mr;
        *va = gpa2hva(&tmp_mr, phys, len, NULL);
        return (bool)true;
    };

    iosfc_desc.unmapMemory = ^(void *a, void *b, void *c, void *d, void *e, void *f) {
        trace_apple_iosfc_unmap_memory(a, b, c, d, e, f);
        return (bool)true;
    };

    iosfc_desc.raiseInterrupt = ^(uint32_t vector) {
        trace_apple_iosfc_raise_irq(vector);
        bool locked = qemu_mutex_iothread_locked();
        if (!locked) {
            qemu_mutex_lock_iothread();
        }
        qemu_irq_pulse(s->irq_iosfc);
        if (!locked) {
            qemu_mutex_unlock_iothread();
        }
        return (bool)true;
    };

    s->pgiosfc = [PGIOSurfaceHostDevice new];
    [s->pgiosfc initWithDescriptor:iosfc_desc];

    QTAILQ_INIT(&s->tasks);

    create_fb(s);
}

static void apple_gfx_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = apple_gfx_reset;
    dc->realize = apple_gfx_realize;
}

static TypeInfo apple_gfx_info = {
    .name          = TYPE_APPLE_GFX,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleGFXState),
    .class_init    = apple_gfx_class_init,
    .instance_init = apple_gfx_init,
};

static void apple_gfx_register_types(void)
{
    type_register_static(&apple_gfx_info);
}

type_init(apple_gfx_register_types)
