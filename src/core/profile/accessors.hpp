#ifndef GHOSTLOCK_PROFILE_ACCESSORS_HPP
#define GHOSTLOCK_PROFILE_ACCESSORS_HPP

#include <cstdint>
#include "kernel/runtime_struct_offsets.h"

namespace ghostlock::profile {

    // 【终极修复点】使用全局绝对双冒号运算符，彻底粉碎任何类成员同名污染 Bug
    inline uintptr_t slide_init_task() { 
        return ::pure_49_init_task(); 
    }
    
    // 4.9 内核不需要现代高版本组件，直接返回 0 安全绕过
    inline uint32_t kernelsnitch_collisions() { return 0; }
    inline uintptr_t slide_nfulnl_logger()    { return 0; }
    inline uintptr_t slide_loggers_0_1()      { return 0; }
    inline uintptr_t slide_random_boot_id_data() { return 0; }
    inline uintptr_t slide_root_task_group()   { return 0; }
    inline uintptr_t slide_sysctl_bootid()     { return 0; }

} // namespace ghostlock::profile

#endif // GHOSTLOCK_PROFILE_ACCESSORS_HPP
