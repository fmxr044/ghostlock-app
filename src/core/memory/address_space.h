#ifndef GHOSTLOCK_ADDRESS_SPACE_H
#define GHOSTLOCK_ADDRESS_SPACE_H

#include "profile/model.h"
#include "kernel/target_constants.hpp"
#include <optional>
#include <cstdint>

namespace ghostlock::memory {
    enum class SocFamily : int32_t {
        Qcom = 0,
        Mtk,
        Xring,
        Google,
    };

    /* Addresses derived once from an immutable target profile and the device SoC.
 * This is the authoritative input for image-to-direct-map translation. */
    struct ResolvedAddresses {
        SocFamily soc;
        target::KernelAddress<target::PhysicalAddressDomain> kernel_phys_load;
        /* DRAM base (linear-map PHYS_OFFSET). Defaults to the compiled
         * P0_PHYS_OFFSET; a profile may override it via kernel_phys_offset. */
        uintptr_t phys_offset = 0;
        target::KernelAddress<target::ImageAddressDomain> init_cred_image;

        // 【终极修复补全】为 Linux 4.9.227 显式声明这个用来挂载硬编码对齐后运行时虚拟 text 基准的变量
        uintptr_t kernel_virtual_start = 0;

        int32_t init(const ghostlock::profile::TargetProfile *profile);

        int32_t init_for_soc(const ghostlock::profile::TargetProfile *profile, SocFamily family);

        uintptr_t data_alias(uintptr_t image_addr) const;

        std::optional<target::KernelAddress<target::DirectMapAddressDomain> > data_alias_checked(
            target::KernelAddress<target::ImageAddressDomain> image_address) const noexcept;

        [[nodiscard]] uint64_t phys_load() const {
            return kernel_phys_load.value();
        }

        [[nodiscard]] uintptr_t init_cred_image_addr() const {
            return init_cred_image.value();
        }

        [[nodiscard]] const char *soc_name(const ghostlock::profile::TargetProfile *profile) const;
    };
} // namespace ghostlock::memory

#endif
