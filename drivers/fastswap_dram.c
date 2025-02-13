#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/directswap.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/vmalloc.h>
#include <linux/path.h>
#include "fastswap_dram.h"


#define ONEGB (1024UL*1024*1024)
#define ALIGNMENT (4096UL)
#define REMOTE_BUF_SIZE (ONEGB * 32) /* must match what server is allocating */
#define TOTAL_PAGES (8UL*1024*1024)
#define ALLOC_DAEMON_CORE 40
#define FREE_DAEMON_CORE 41
#define NUM_BW_ISOLATION 16
#define NUM_ONLINE_CORE 64

static void *drambuf;
static void *local_partition_start;
extern struct allocator_page_queues *queues_allocator;
extern struct deallocator_page_queues *queues_deallocator;

static struct task_struct *thread_alloc;
//static struct task_struct *thread_alloc_reclaim;
static struct task_struct *thread_free;

spinlock_t bw_lock[NUM_BW_ISOLATION];
int core_to_isolation[NUM_ONLINE_CORE];

atomic64_t num_swapout = ATOMIC64_INIT(0);

struct GlobalPageQueue {
    atomic64_t begin;
    atomic64_t end;
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

    while(get_length_queue() == 0) ;
    prev_begin = atomic64_read(&global_page_queue->begin);
    atomic64_set(&global_page_queue->begin, (prev_begin + 1) % TOTAL_PAGES);
    while(atomic64_read(&global_page_queue->pages[prev_begin]) == 0) ;
    ret = atomic64_read(&global_page_queue->pages[prev_begin]);
    atomic64_set(&global_page_queue->pages[prev_begin], 0);
    //pr_info("pop_queue_allocator success.\n");
    return ret;
}

int push_queue(uint64_t page_addr) {
   
    uint64_t prev_end = atomic64_read(&global_page_queue->end);

    while (get_length_queue() >= TOTAL_PAGES - 1);
    atomic64_set(&global_page_queue->end, (prev_end + 1) % TOTAL_PAGES);
    atomic64_set(&global_page_queue->pages[prev_end], page_addr);

    return 0;
}


int direct_swap_rdma_read_async(struct page *page, u64 roffset, int type) {
	void *page_vaddr;
  //uint32_t nproc = raw_smp_processor_id();
 
  
  //spin_lock(&bw_lock[core_to_isolation[nproc]]);

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageUptodate(page), page);

	page_vaddr = kmap_atomic(page);
	copy_page(page_vaddr, (void *) (local_partition_start + (roffset <<  PAGE_SHIFT)));
	kunmap_atomic(page_vaddr);

	SetPageUptodate(page);
	unlock_page(page);

  //spin_unlock(&bw_lock[core_to_isolation[nproc]]);
	return 0;
}
EXPORT_SYMBOL(direct_swap_rdma_read_async);

int direct_swap_rdma_read_sync(struct page *page, u64 roffset, int type) {
	return direct_swap_rdma_read_async(page, roffset, type);
}
EXPORT_SYMBOL(direct_swap_rdma_read_sync);

int direct_swap_rdma_write(struct page *page, u64 roffset, int type) {
	void *page_vaddr;
  //uint32_t nproc = raw_smp_processor_id();

  //spin_lock(&bw_lock[core_to_isolation[nproc]]);

  //BUG_ON(type != core_id_to_swap_type[nproc]);

	page_vaddr = kmap_atomic(page);
	copy_page((void *) (local_partition_start + (roffset <<  PAGE_SHIFT)), page_vaddr);
	kunmap_atomic(page_vaddr);


  //spin_unlock(&bw_lock[core_to_isolation[nproc]]);
  //atomic64_inc(&num_swapout);
  //if(atomic64_read(&num_swapout) % 100000 == 0) {
  //  pr_info("Running on core: %d\n", raw_smp_processor_id());
  //}

	return 0;
}
EXPORT_SYMBOL(direct_swap_rdma_write);


int sswap_rdma_write(struct page *page, u64 roffset)
{
	void *page_vaddr;

	page_vaddr = kmap_atomic(page);
	copy_page((void *) (drambuf + (roffset <<  PAGE_SHIFT)), page_vaddr);
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

	VM_BUG_ON_PAGE(!PageSwapCache(page), page);
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	VM_BUG_ON_PAGE(PageUptodate(page), page);

	page_vaddr = kmap_atomic(page);
	copy_page(page_vaddr, (void *) (drambuf + (roffset <<  PAGE_SHIFT)));
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

int sswap_rdma_drain_loads_sync(int cpu, int target)
{
	return 1;
}
EXPORT_SYMBOL(sswap_rdma_drain_loads_sync);

static void __exit sswap_dram_cleanup_module(void)
{
	vfree(drambuf);
}

static int free_daemon(void* data) {
  uint64_t id, count;
  uint64_t addr;
  uint64_t cur_queue_deallocator_len;
  /*
  * [DirectSwap] Recycle pages
  */

  while(!kthread_should_stop()) {
    
    for(id = 0;id < NUM_KFIFOS_FREE; ++id) {
      count++;
      cur_queue_deallocator_len = get_length_deallocator(id);
      if(cur_queue_deallocator_len > 0) {
        addr = pop_queue_deallocator(id);
        push_queue(addr);
      }
        
      if(count % 5000000 == 0)
        cond_resched();
    }
    
  }

  return 0;
}
  

static int alloc_daemon(void* data) {
  uint64_t id, count;
  uint64_t addr;
  uint64_t cur_queue_allocator_len;

  /*
  * [DirectSwap] Fill pages
  */
  while(!kthread_should_stop()) {

    for(id = 0;id < NUM_KFIFOS_ALLOC; ++id) {
      count++;
      cur_queue_allocator_len = get_length_allocator(id);
      if(cur_queue_allocator_len < ALLOCATE_BUFFER_SIZE - 1) {
        addr = pop_queue();
        push_queue_allocator(addr, id);
      }
        
      if(count % 5000000 == 0)
        cond_resched();
    }
  }

  return 0;   
}


static int __init sswap_dram_init_module(void)
{
    int i;
    uint64_t idx;
	  pr_info("start: %s\n", __FUNCTION__);
	  pr_info("will use new DRAM backend");
    BUG_ON(!queues_allocator);
    BUG_ON(!queues_deallocator);

	  drambuf = vzalloc(REMOTE_BUF_SIZE + (1 << PAGE_SHIFT));
    local_partition_start = (void*)(((uint64_t)drambuf + ALIGNMENT - 1) & ~(ALIGNMENT - 1));
	  pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

	  pr_info("DRAM backend is ready for reqs\n");

    global_page_queue = (struct GlobalPageQueue*) vzalloc(sizeof(struct GlobalPageQueue));
    atomic64_set(&global_page_queue->begin, 0);
    atomic64_set(&global_page_queue->end, 0);
    for(idx = 0;idx < TOTAL_PAGES; ++idx) {
      atomic64_set(&global_page_queue->pages[idx], 0);
    }

    idx = 1;
    while(get_length_queue() < TOTAL_PAGES - 10) {
      push_queue((uint64_t)local_partition_start + (idx << PAGE_SHIFT));
      idx++;
    }

    thread_alloc = kthread_create(alloc_daemon, NULL, "directswap_alloc_daemon");
    if (IS_ERR(thread_alloc)) {
        printk(KERN_ERR "Failed to create kernel thread: thread alloc.\n");
        return PTR_ERR(thread_alloc);
    } 


    thread_free = kthread_create(free_daemon, NULL, "directswap_free_daemon");
    if (IS_ERR(thread_free)) {
        printk(KERN_ERR "Failed to create kernel thread: thread free.\n");
        return PTR_ERR(thread_free);
    } 

    for (i = 0; i < NUM_BW_ISOLATION; i++) {
      spin_lock_init(&bw_lock[i]);
    }
    
    for(i = 0;i < NUM_ONLINE_CORE; ++i) {
      core_to_isolation[i] = NUM_BW_ISOLATION - 1;
    }

    core_to_isolation[0] = 0;
    

    kthread_bind(thread_alloc, ALLOC_DAEMON_CORE);
    wake_up_process(thread_alloc);

    kthread_bind(thread_free, FREE_DAEMON_CORE);
    wake_up_process(thread_free);

	  return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
