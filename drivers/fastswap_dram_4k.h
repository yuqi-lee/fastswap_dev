#if !defined(_SSWAP_DRAM_H)
#define _SSWAP_DRAM_H

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/rhashtable.h>
#include <linux/list.h>

#define TOTAL_PAGES (8UL*1024*1024)


struct timer_list swap_pages_timer;
struct timer_list gc_timer;

atomic64_t num_swap_pages = ATOMIC64_INIT(0);
atomic64_t num_free_fail = ATOMIC64_INIT(0);
atomic64_t num_swapin_pages = ATOMIC64_INIT(0);
atomic64_t num_swapout_pages = ATOMIC64_INIT(0);
atomic64_t num_swapfree_pages = ATOMIC64_INIT(0);

uint64_t offset_to_rpage_addr[TOTAL_PAGES] = {0};
uint32_t offset_to_rkey[TOTAL_PAGES] = {0};


int sswap_rdma_read_async(struct page *page, u64 roffset);
int sswap_rdma_read_sync(struct page *page, u64 roffset);
int sswap_rdma_write(struct page *page, u64 roffset);
int sswap_rdma_poll_load(int cpu);
int sswap_rdma_drain_loads_sync(int cpu, int target);
void sswap_rdma_free_page(uint64_t roffset);


uint64_t alloc_remote_page(void);
void free_remote_page(uint64_t raddr);
uint32_t get_rkey(uint64_t raddr);

#endif
