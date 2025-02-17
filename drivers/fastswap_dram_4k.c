#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include "fastswap_dram_4k.h"

#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 33) /* must match what server is allocating */
#define NUM_ONLINE_CPUS 128
#define GC_INTERVAL 500
#define INFO_PRINT_TINTERVAL 1000

#define TIME_NOW (ktime_get_ns())
#define TIME_DURATION_US(START, END) \
    ((long)((END) - (START)) / 1000)

static void *drambuf;
static void *local_partition_start;

struct GlobalPageQueue {
    atomic64_t begin;
    atomic64_t end;
	spinlock_t lock;
    atomic64_t pages[TOTAL_PAGES];
};

static struct GlobalPageQueue* global_page_queue = NULL;

uint64_t get_length_queue(void) {
    uint64_t begin = atomic64_read(&global_page_queue->begin);
    uint64_t end = atomic64_read(&global_page_queue->end);
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (TOTAL_PAGES - begin + end);
    }
}

uint64_t pop_queue(void) {
    uint64_t ret = 0;
    uint64_t prev_begin;

	spin_lock(&global_page_queue->lock);

    while(get_length_queue() == 0) ;
    prev_begin = atomic64_read(&global_page_queue->begin);
    atomic64_set(&global_page_queue->begin, (prev_begin + 1) % TOTAL_PAGES);
    while(atomic64_read(&global_page_queue->pages[prev_begin]) == 0) ;
    ret = atomic64_read(&global_page_queue->pages[prev_begin]);
    atomic64_set(&global_page_queue->pages[prev_begin], 0);
    //pr_info("pop_queue_allocator success.\n");
    spin_unlock(&global_page_queue->lock);

    return ret;
}

int push_queue(uint64_t page_addr) {
    uint64_t prev_end;

    spin_lock(&global_page_queue->lock);
    prev_end = atomic64_read(&global_page_queue->end);

    while (get_length_queue() >= TOTAL_PAGES - 1) ;
    atomic64_set(&global_page_queue->end, (prev_end + 1) % TOTAL_PAGES);
    atomic64_set(&global_page_queue->pages[prev_end], page_addr);
	spin_unlock(&global_page_queue->lock);
    return 0;
}


void free_remote_page(uint64_t raddr) {
    uint64_t start;
    start = TIME_NOW;
    while(TIME_DURATION_US(start, TIME_NOW) < 8) {
        ;
    }

    push_queue(raddr);
}
EXPORT_SYMBOL(free_remote_page);


uint64_t alloc_remote_page(void) {
    uint64_t start, raddr;
    start = TIME_NOW;
    while(TIME_DURATION_US(start, TIME_NOW) < 8) {
        ;
    }

    raddr = pop_queue();
    return raddr;
}
EXPORT_SYMBOL(alloc_remote_page);


int sswap_rdma_write(struct page *page, u64 roffset)
{
  	uint64_t raddr = offset_to_rpage_addr[roffset];
	void *page_vaddr;
    uint64_t start;
    start = TIME_NOW;
    while(TIME_DURATION_US(start, TIME_NOW) < 6) {
        ;
    }



  	BUG_ON(roffset >= TOTAL_PAGES);
  	VM_BUG_ON_PAGE(!PageSwapCache(page), page);

  	if(raddr == 0) {
    	raddr = alloc_remote_page();
    	if(raddr == 0) {
      		pr_err("bad remote page alloc\n");
      		return -1;
    	}
    	offset_to_rpage_addr[roffset] = raddr;
  	}

    atomic64_inc(&num_swap_pages);
	page_vaddr = kmap_atomic(page);
	copy_page((void *)raddr , page_vaddr);
	kunmap_atomic(page_vaddr);

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
	uint64_t raddr = offset_to_rpage_addr[roffset];
    uint64_t start;
    start = TIME_NOW;
    while(TIME_DURATION_US(start, TIME_NOW) < 6) {
        ;
    }


  	BUG_ON(roffset >= TOTAL_PAGES);
  	BUG_ON(raddr == 0);
  	BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
  	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  	VM_BUG_ON_PAGE(!PageLocked(page), page);
  	VM_BUG_ON_PAGE(PageUptodate(page), page);

	page_vaddr = kmap_atomic(page);
	copy_page(page_vaddr, (void *)raddr);
	kunmap_atomic(page_vaddr);

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

void sswap_rdma_free_page(u64 roffset) {
  	BUG_ON(roffset >= TOTAL_PAGES);

  	if(offset_to_rpage_addr[roffset] == 0) {
    	return;
  	}
  	free_remote_page(offset_to_rpage_addr[roffset]);
  	offset_to_rpage_addr[roffset] = 0;
  	atomic64_dec(&num_swap_pages);

	return;
}
EXPORT_SYMBOL(sswap_rdma_free_page);


int sswap_rdma_drain_loads_sync(int cpu, int target)
{
	return 1;
}
EXPORT_SYMBOL(sswap_rdma_drain_loads_sync);

static void __exit sswap_dram_cleanup_module(void)
{
	vfree(drambuf);
    vfree(global_page_queue);
}

static int __init sswap_dram_init_module(void)
{
	uint64_t idx;
	pr_info("start: %s\n", __FUNCTION__);
	pr_info("will use new DRAM backend");

	drambuf = vzalloc(REMOTE_BUF_SIZE + (1 << PAGE_SHIFT));
    local_partition_start = (void*)(((uint64_t)drambuf + (1 << PAGE_SHIFT) - 1) & ~((1 << PAGE_SHIFT) - 1));
	pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

    global_page_queue = (struct GlobalPageQueue*) vzalloc(sizeof(struct GlobalPageQueue));
	if(!global_page_queue) {
		pr_err("Bad vzalloc for global_page_queue.\n");
	}
	//spin_lock_init(&global_page_queue->lock);
    atomic64_set(&global_page_queue->begin, 0);
    atomic64_set(&global_page_queue->end, 0);
    for(idx = 0;idx < TOTAL_PAGES; ++idx) {
      atomic64_set(&global_page_queue->pages[idx], 0);
    }

	idx = 1;
    while(get_length_queue() < TOTAL_PAGES - 10) {
      push_queue((uint64_t)local_partition_start + (idx * (1 << PAGE_SHIFT)));
      idx++;
    }

    spin_lock_init(&global_page_queue->lock);


	pr_info("DRAM backend is ready for reqs\n");
	return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
