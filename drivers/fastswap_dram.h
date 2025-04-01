#if !defined(_SSWAP_DRAM_H)
#define _SSWAP_DRAM_H

#include <linux/module.h>
#include <linux/vmalloc.h>

atomic64_t num_swapout_pages = ATOMIC64_INIT(0);
atomic64_t num_swapin_pages = ATOMIC64_INIT(0);
struct timer_list swap_pages_timer;

int sswap_rdma_read_async(struct page *page, u64 roffset);
int sswap_rdma_read_sync(struct page *page, u64 roffset);
int sswap_rdma_write(struct page *page, u64 roffset);
int sswap_rdma_poll_load(int cpu);
int sswap_rdma_drain_loads_sync(int cpu, int target);

#endif
