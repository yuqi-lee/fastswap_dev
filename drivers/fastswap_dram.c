#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/delay.h>
#include "fastswap_dram.h"

#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 32) /* must match what server is allocating */

#define INFO_PRINT_TINTERVAL 1000

static void *drambuf;

uint64_t prev_num_swapout_pages = 0;
uint64_t prev_num_swapin_pages = 0;

void swap_pages_timer_callback(struct timer_list *timer) {
  uint64_t num_swapout_pages_tmp = atomic64_read(&num_swapout_pages);
  uint64_t num_swapin_pages_tmp = atomic64_read(&num_swapin_pages);
  int swapout_bw = (num_swapout_pages_tmp - prev_num_swapout_pages) / 1000;
  int swapin_bw = (num_swapin_pages_tmp - prev_num_swapin_pages) / 1000;
  prev_num_swapout_pages = num_swapout_pages_tmp;
  prev_num_swapin_pages = num_swapin_pages_tmp;

  pr_info("swapout bw = %d Kops, swapin bw = %d Kops", swapout_bw, swapin_bw);
  mod_timer(timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL)); 
}

int sswap_rdma_write(struct page *page, u64 roffset)
{
	void *page_vaddr;

	page_vaddr = kmap_atomic(page);
	copy_page((void *) (drambuf + roffset), page_vaddr);
	kunmap_atomic(page_vaddr);
	udelay(5);
	atomic64_inc(&num_swapout_pages);
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_write);

int sswap_rdma_poll_load(int cpu)
{
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

int sswap_rdma_read_async(struct page *page, u64 roffset)
{
	void *page_vaddr;

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageUptodate(page), page);

	page_vaddr = kmap_atomic(page);
	copy_page(page_vaddr, (void *) (drambuf + roffset));
	kunmap_atomic(page_vaddr);
	udelay(5);
	atomic64_inc(&num_swapin_pages);

	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
	return sswap_rdma_read_async(page, roffset);
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_drain_loads_sync(int cpu, int target)
{
	return 1;
}
EXPORT_SYMBOL(sswap_rdma_drain_loads_sync);

static void __exit sswap_dram_cleanup_module(void)
{
	vfree(drambuf);
}

static int __init sswap_dram_init_module(void)
{
	pr_info("start: %s\n", __FUNCTION__);
	pr_info("will use new DRAM backend");

	drambuf = vzalloc(REMOTE_BUF_SIZE);
	pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

	pr_info("DRAM backend is ready for reqs\n");

	timer_setup(&swap_pages_timer, swap_pages_timer_callback, 0);
    mod_timer(&swap_pages_timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL));

	return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
