#ifndef QEMU_APPLE_GFX_H
#define QEMU_APPLE_GFX_H

#define TYPE_APPLE_GFX_VMAPPLE      "apple-gfx-vmapple"
#define TYPE_APPLE_GFX_PCI          "apple-gfx-pci"

#ifdef __OBJC__

#include "qemu/osdep.h"
#include "exec/memory.h"
#include "ui/surface.h"
#import <ParavirtualizedGraphics/ParavirtualizedGraphics.h>

typedef QTAILQ_HEAD(, PGTask_s) AppleGFXTaskList;

typedef struct AppleGFXState {
    MemoryRegion iomem_gfx;
    id<PGDevice> pgdev;
    id<PGDisplay> pgdisp;
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


void apple_gfx_common_init(Object *obj, AppleGFXState *s, const char* obj_name);
void apple_gfx_common_realize(AppleGFXState *s, PGDeviceDescriptor *desc);

#endif

#endif
