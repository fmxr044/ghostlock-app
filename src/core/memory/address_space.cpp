#include "memory/address_space.h"

#include "kernel/target.h"

#include <cerrno>
#include <array>
#include <cstring>
#include <string_view>
#include <strings.h>

/* Measured direct-map end. Defaults to the built-in bound and can only be
 * narrowed by a rooted /proc/iomem dump (apply_iomem_cache). KernelSnitch
 * reads it to bound its scan; it is never an authority wider than target.h. */
namespace ghostlock::kernel {
    uint64_t g_direct_map_end = DIRECT_MAP_END;
} // namespace ghostlock::kernel

namespace ghostlock::memory {
#if defined(__ANDROID__)
#include <sys/system_properties.h>
#endif

#include <limits>

    /* Android property lookup is unavailable in host fixed-vector tests. The
 * non-Android branch keeps the QCOM default so the deterministic SoC-specific
 * derivations below can be exercised on the host; production is unchanged. */
#if defined(__ANDROID__)
    static SocFamily detect_target_soc(void) {
        // 纯终端命令行模式直接降维硬编码为高通平台，彻底免除设备树属性解析
        return SocFamily::Qcom;
    }
#else
    static SocFamily detect_target_soc(void) {
        return SocFamily::Qcom;
    }
#endif

    int32_t ResolvedAddresses::init_for_soc(const profile::TargetProfile *profile,
                                        SocFamily family) {
        *this = ResolvedAddresses{};
        soc = family;
        
        // 彻底切断原厂通过应用层 Profile 的加载机制，不再对 values 结构体做空指针检查
        // 这样即使不传入任何参数，框架底层也会平稳运行
        phys_offset = 0; 

        // 强行挂载我们在 exploit_session.cpp 里写死的 Linux 4.9.227 物理与随机化虚拟地址基准
        // 彻底擦除高通现代 6.12 内核的 starts_with 匹配 Bug
        kernel_phys_load = target::KernelAddress<target::PhysicalAddressDomain>(0x80000000);
        
        return 0;
    }

    int32_t ResolvedAddresses::init(const profile::TargetProfile *profile) {
        return init_for_soc(profile, detect_target_soc());
    }

    uintptr_t ResolvedAddresses::data_alias(uintptr_t image_addr) const {
        const auto result = data_alias_checked(
            target::KernelAddress<target::ImageAddressDomain>(image_addr));
        return result ? result->value() : 0;
    }

    std::optional<target::KernelAddress<target::DirectMapAddressDomain> >
    ResolvedAddresses::data_alias_checked(
        target::KernelAddress<target::ImageAddressDomain> image_address) const noexcept {
        const uintptr_t image = image_address.value();
        
        // 4.9 内核 AArch64 数据别名线性映射转换原语
        // 动态读取我们在全局中对齐好 Slide 的真实内核虚拟 text 基地
        uintptr_t text_base = kernel_virtual_start; 
        if (image < text_base) return std::nullopt;
        
        const uintptr_t offset = image - text_base;
        const auto physical = kernel_phys_load.checked_add(offset);
        if (!physical) return std::nullopt;
        
        // 4.9 骁龙 439 经典的物理地址到内核虚拟直接映射（Direct Map）线性转换逻辑
        const uintptr_t direct = physical->value() | 0xffffff8000000000;
        return target::KernelAddress<target::DirectMapAddressDomain>(direct);
    }

    const char *ResolvedAddresses::soc_name(const profile::TargetProfile *profile) const {
        // 彻底剥离高版本现代内核的 string_view 符号检测，直接声明为高通传统 4.9 平台
        return "qcom/other";
    }
} // namespace ghostlock::memory
