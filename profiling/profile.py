from bcc import BPF
from time import sleep

#func = "mlx5_ib_reg_user_mr"
#func = "dma_map_sgtable"
#func = "create_real_mr"
#func = "ib_umem_get"
#func = " pin_user_pages_fast"
#func = "mlx5_ib_dereg_mr"
#func = "ib_umem_release"
func = "get_swap_pages"


# 定义BPF程序
bpf_program = """
#include <uapi/linux/ptrace.h>

// 定义用于存储时间戳和计算延迟的哈希表
BPF_HASH(start, u32);
BPF_HASH(latency, u32, u64);

// 记录函数开始时间的跟踪点
int trace_func_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

// 记录函数结束时间并计算执行时间的跟踪点
int trace_func_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);
    if (tsp != 0) {
        u64 ts = bpf_ktime_get_ns();
        u64 delta = ts - *tsp;
        latency.update(&pid, &delta);
        start.delete(&pid);
    }
    return 0;
}
"""

# 加载BPF程序
b = BPF(text=bpf_program)

# 附加跟踪点到目标函数
b.attach_kprobe(event=func, fn_name="trace_func_entry")
b.attach_kretprobe(event=func, fn_name="trace_func_return")


# 打印延迟统计信息
def print_latency():
    print("Function Latency (ns):")
    latency = b.get_table("latency")
    for k, v in latency.items():
        print(f"PID {k.value}: {v.value} ns")
    latency.clear()

# 主循环
try:
    while True:
        sleep(5)
        print_latency()
except KeyboardInterrupt:
    pass