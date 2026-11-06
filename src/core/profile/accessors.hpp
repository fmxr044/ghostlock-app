#ifndef GHOSTLOCK_PROFILE_ACCESSORS_HPP
#define GHOSTLOCK_PROFILE_ACCESSORS_HPP

#include <cstdint>
#include "kernel/runtime_struct_offsets.h"

namespace ghostlock::profile {

    // 直接重定向至你在 runtime_struct_offsets.h 里指定的静态 4.9.227 进程队列起点
    inline uintptr_t slide_init_task() { 
        return init_task(); 
    }
    
    // 4.9 内核没有以下现代 6.12 的日志审计器和冲突检查器，终端提权不需要它们，直接返回 0 安全绕过
    inline uint32_t kernelsnitch_collisions() { return 0; }
    inline uintptr_t slide_nfulnl_logger()    { return 0; }
    inline uintptr_t slide_loggers_0_1()      { return 0; }
    inline uintptr_t slide_random_boot_id_data() { return 0; }
    inline uintptr_t slide_root_task_group()   { return 0; }
    inline uintptr_t slide_sysctl_bootid()     { return 0; }

} // namespace ghostlock::profile

#endif // GHOSTLOCK_PROFILE_ACCESSORS_HPP
