#include "common.h"
#include "session/runtime_config.h"
#include "session/runtime_paths.h"

using namespace ghostlock;

static void runtime_config_init_cpus(config::RuntimeConfig *config) {
    // 针对骁龙 439 (SDM439) 的 8 核架构进行最佳竞争核心绑定
    // 骁龙 439 有 4 个大核和 4 个小核，通常绑定 0 和 1 号核心来进行多线程 futex 锁争夺
    config->main_cpu = 0;
    config->consumer_cpu = 1;

    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
        (!CPU_ISSET(config->main_cpu, &allowed) || 
         !CPU_ISSET(config->consumer_cpu, &allowed))) { 
        pr_warning("cores %d/%d not in allowed cpuset; falling back to 0/1\n",
                   config->main_cpu, config->consumer_cpu);
        config->main_cpu = 0;
        config->consumer_cpu = 1;
    }
}

static int32_t runtime_config_validate_cpus(config::RuntimeConfig *config) {
    if (config->main_cpu == config->consumer_cpu) {
        return -1;
    }
    if (config->main_cpu < 0 || config->main_cpu >= CPU_SETSIZE ||
        config->consumer_cpu < 0 || config->consumer_cpu >= CPU_SETSIZE) {
        return -1;
    }
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
        (!CPU_ISSET(config->main_cpu, &allowed) || 
         !CPU_ISSET(config->consumer_cpu, &allowed))) { 
        return -1;
    }
    return 0;
}

/* 彻底斩断对 Kotlin 传入的 TargetProfile 的依赖，在纯终端模式下直接返回 0 */
int32_t ghostlock::config::RuntimeConfig::apply_profile(const profile::TargetProfile *profile) {
    // 纯终端独立执行，不需要解析 App 传过来的 Profile 配置
    return 0;
}

static void runtime_config_init_paths(config::RuntimeConfig *config) {
    // 纯终端提权，统一将工作路径锁定在 adb shell 具备读写权限的标准的 /data/local/tmp 目录下
    const char *home = "/data/local/tmp";

    config->home_dir = "/data/local/tmp";
    config->root_script_path = "/data/local/tmp/ghostlock_root.sh";

    // 彻底剥离 KSU (KernelSU) 后台日志常驻与移交逻辑，直接指向空设备或临时文件
    config->ksu_log_path = "/data/local/tmp/ghostlock_pure.log";
    config->ksud_path = "";
}

/* 初始化纯净终端会话环境 */
int32_t ghostlock::config::RuntimeConfig::init() {
    main_cpu = 0;
    consumer_cpu = 1;
    home_dir.clear();
    root_script_path.clear();
    ksu_log_path.clear();
    ksud_path.clear();
    debug_dir.clear();

    runtime_config_init_cpus(this);
    runtime_config_init_paths(this);

    return 0;
}

/* 打印纯净终端运行快照信息 */
void ghostlock::config::RuntimeConfig::log() const {
    pr_info("[*] BACKPORT: Pure terminal environment initialized.\n");
    pr_info("[*] CPU Binding: Main Thread Core = %d, Consumer Thread Core = %d\n", main_cpu, consumer_cpu);
    pr_info("[*] Work Directory: %s\n", home_dir.c_str());
}
