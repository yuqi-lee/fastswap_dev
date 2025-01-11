#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include "fastswap_dram_random.h"

#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 33) /* must match what server is allocating */
#define NUM_ONLINE_CPUS 128
#define GC_INTERVAL 500
#define INFO_PRINT_TINTERVAL 1000
#define MB_SHIFT 20

static void *drambuf;
static void *local_partition_start;

struct GlobalBlockQueue {
    atomic64_t begin;
    atomic64_t end;
	//spinlock_t lock;
    atomic64_t pages[TOTAL_BLOCKS];
};

static struct GlobalBlockQueue* global_block_queue = NULL;

uint64_t get_length_queue(void) {
    uint64_t begin = atomic64_read(&global_block_queue->begin);
    uint64_t end = atomic64_read(&global_block_queue->end);
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (TOTAL_BLOCKS - begin + end);
    }
}

uint64_t pop_queue(void) {
    uint64_t ret = 0;
    uint64_t prev_begin;

	//spin_lock(&global_block_queue->lock);

    while(get_length_queue() == 0) ;
    prev_begin = atomic64_read(&global_block_queue->begin);
    atomic64_set(&global_block_queue->begin, (prev_begin + 1) % TOTAL_BLOCKS);
    while(atomic64_read(&global_block_queue->pages[prev_begin]) == 0) ;
    ret = atomic64_read(&global_block_queue->pages[prev_begin]);
    atomic64_set(&global_block_queue->pages[prev_begin], 0);
    //pr_info("pop_queue_allocator success.\n");
	//spin_unlock(&global_block_queue->lock);

    return ret;
}

int push_queue(uint64_t page_addr) {
    uint64_t prev_end;

    //spin_lock(&global_block_queue->lock);
    prev_end = atomic64_read(&global_block_queue->end);

    while (get_length_queue() >= TOTAL_BLOCKS - 1) ;
    atomic64_set(&global_block_queue->end, (prev_end + 1) % TOTAL_BLOCKS);
    atomic64_set(&global_block_queue->pages[prev_end], page_addr);
	//spin_unlock(&global_block_queue->lock);
    return 0;
}


// must obtain free_blocks_tree_lock when excute this function
void free_remote_block(struct block_info *bi) {
	BUG_ON(bi->free_list_idx >= NUM_FREE_BLOCKS_LIST);
    list_del(&bi->block_node_list);
    rhashtable_remove_fast(blocks_map, &bi->block_node_rhash, blocks_map_params);

    //add_free_cache(bi->raddr/*, bi->rkey*/);
	push_queue(bi->raddr);
    kfree(bi);

    atomic64_inc(&num_free_blocks);
}
EXPORT_SYMBOL(free_remote_block);

void free_remote_page(uint64_t raddr) {
    struct block_info *bi = NULL;
    uint64_t raddr_block; 
    uint64_t offset; 
    uint32_t nproc = raw_smp_processor_id();
    uint32_t free_list_idx = nproc % NUM_FREE_BLOCKS_LIST;
    //uint32_t count = 0;
    
    BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
    spin_lock(&global_lock);

    raddr_block = raddr >> BLOCK_SHIFT;
    raddr_block = raddr_block << BLOCK_SHIFT;
    bi = rhashtable_lookup_fast(blocks_map, &raddr_block, blocks_map_params);
    if(!bi) {
        pr_err("the page being free(%p) is not exit: cannot find out block_info.\n", (void*)raddr);
        spin_unlock(&global_lock);
        return;
    }

    BUG_ON(raddr_block != bi->raddr);
    BUG_ON(raddr < bi->raddr);

    //spin_lock(&free_blocks_tree_locks[free_tree_idx]);
    //spin_lock(&bi->block_lock);
    

    offset = (raddr - bi->raddr) >> PAGE_SHIFT;
    BUG_ON(offset >= (RBLOCK_SIZE >> PAGE_SHIFT));
	BUG_ON(!test_bit(offset, bi->rpages_bitmap));
	BUG_ON(bi->cnt >= (RBLOCK_SIZE >> PAGE_SHIFT));

    clear_bit(offset, bi->rpages_bitmap);

	if(bi->cnt == 0) {
		BUG_ON(bi->free_list_idx != NUM_FREE_BLOCKS_LIST);

		
        bi->free_list_idx = free_list_idx;
	} else {
		BUG_ON(bi->free_list_idx >= NUM_FREE_BLOCKS_LIST);

		//rb_erase(&bi->block_node_rbtree, &free_blocks_trees[bi->free_tree_idx]);
		//bi->free_tree_idx = free_tree_idx;
	}
    bi->cnt += 1;
	list_add(&bi->block_node_list, &free_blocks_lists[free_list_idx]);

    //spin_unlock(&bi->block_lock);
    //spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
    spin_unlock(&global_lock);
}
EXPORT_SYMBOL(free_remote_page);

// must obtain "free_blocks_tree_lock" when excute this function
int alloc_remote_block(uint32_t free_list_idx) {
    struct block_info *bi;
    uint64_t raddr_ = 0;
    uint32_t rkey_ = 0;

    raddr_ = pop_queue();
    if(raddr_ == 0) {
        pr_err("alloc_remote_block failed on pop global queue.\n");
        return -1;
    }
    
    bi = kmalloc(sizeof(struct block_info), GFP_KERNEL);
    if(!bi) {
        pr_err("init block meta data failed.\n");
        return -1;
    }

    // block_info init
    bi->raddr = raddr_;
    bi->rkey = rkey_;
    bi->cnt = (RBLOCK_SIZE >> PAGE_SHIFT);
    bi->free_list_idx = free_list_idx;
    spin_lock_init(&bi->block_lock);
    bitmap_zero(bi->rpages_bitmap, RBLOCK_SIZE >> PAGE_SHIFT);
    INIT_LIST_HEAD(&bi->block_node_list);

    // insert to rhashtable (blocks_map)
    rhashtable_insert_fast(blocks_map, &bi->block_node_rhash, blocks_map_params);
    list_add(&bi->block_node_list, &free_blocks_lists[free_list_idx]);

    atomic64_inc(&num_alloc_blocks);
    return 0;
}
EXPORT_SYMBOL(alloc_remote_block);

uint64_t alloc_remote_page(void) {
    struct block_info *bi/*, *entry, *next_entry*/;
    uint64_t offset;
    uint64_t raddr;
    int ret;
    //int counter = 0;
    //int flag;
    uint32_t nproc = raw_smp_processor_id();
    uint32_t free_list_idx = nproc % NUM_FREE_BLOCKS_LIST;
    //uint32_t raw_free_tree_idx = free_tree_idx;
    //uint8_t locked = 0;

    spin_lock(&global_lock);

    if(list_empty(&free_blocks_lists[free_list_idx])) {
        ret = alloc_remote_block(free_list_idx);
        if(ret) {
            pr_err("can not alloc remote block.\n");
            //spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
            spin_unlock(&global_lock);
            return 0;
        }
    }

    bi = list_first_entry(&free_blocks_lists[free_list_idx], struct block_info, block_node_list);

    //BUG_ON(bi->free_list_idx != free_list_idx);
    if(bi->free_list_idx != free_list_idx) {
        pr_err("block_info's free_tree_idx error: 2\n");
    }

    //spin_lock(&bi->block_lock);
    offset = find_first_zero_bit(bi->rpages_bitmap, RBLOCK_SIZE >> PAGE_SHIFT);
    BUG_ON(offset >= (RBLOCK_SIZE >> PAGE_SHIFT));
    set_bit(offset, bi->rpages_bitmap);
    
    bi->cnt -= 1;
    BUG_ON(bi->cnt > (RBLOCK_SIZE >> PAGE_SHIFT));

    if(bi->cnt == 0) {
        list_del(&bi->block_node_list);
        bi->free_list_idx = NUM_FREE_BLOCKS_LIST;
    }
    spin_unlock(&global_lock);

    raddr = bi->raddr + (offset << PAGE_SHIFT);
    return raddr;
}
EXPORT_SYMBOL(alloc_remote_page);


int sswap_rdma_write(struct page *page, u64 roffset)
{
  	uint64_t raddr = offset_to_rpage_addr[roffset];
	void *page_vaddr;


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

void swap_pages_timer_callback(struct timer_list *timer) {
  int num_swap_pages_tmp = atomic64_read(&num_swap_pages);
  int num_alloc_blocks_tmp = atomic64_read(&num_alloc_blocks);
  int num_free_blocks_tmp = atomic64_read(&num_free_blocks);
  int num_free_fail_tmp = atomic64_read(&num_free_fail);

  pr_info("used swap memory = %d MB, current alloc memory = %d MB\n", (num_swap_pages_tmp >> (MB_SHIFT - PAGE_SHIFT)), ((num_alloc_blocks_tmp - num_free_blocks_tmp) << (BLOCK_SHIFT - MB_SHIFT)));
  pr_info("num_alloc_blocks = %d, num_free_blocks = %d, num_free_fail = %d\n", num_alloc_blocks_tmp, num_free_blocks_tmp, num_free_fail_tmp);
  mod_timer(timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL)); 
}

void gc_timer_callback(struct timer_list *timer) {
  struct block_info *entry, *next_entry;  
  int i;

  for(i = 0;i < NUM_FREE_BLOCKS_LIST; ++i) {
    //if(spin_trylock(&free_blocks_tree_locks[i])) {
    spin_lock(&global_lock);
	if(spin_trylock(&free_blocks_list_locks[i])) {
        list_for_each_entry_safe(entry, next_entry, &free_blocks_lists[i], block_node_list) {
            spin_lock(&entry->block_lock);
            //BUG_ON(entry->free_list_idx != i);
            if(entry->free_list_idx != i) {
                pr_err("entry's free list idx error: 1\n");
            }
            if(entry->cnt == (RBLOCK_SIZE >> PAGE_SHIFT)) {
                free_remote_block(entry);
                continue;
            }
            spin_unlock(&entry->block_lock);
        }
        spin_unlock(&free_blocks_list_locks[i]);
    }
    spin_unlock(&global_lock);
  }

  mod_timer(timer, jiffies + msecs_to_jiffies(GC_INTERVAL)); 
}

int sswap_rdma_drain_loads_sync(int cpu, int target)
{
	return 1;
}
EXPORT_SYMBOL(sswap_rdma_drain_loads_sync);

static void __exit sswap_dram_cleanup_module(void)
{
	vfree(drambuf);
    vfree(global_block_queue);
    vfree(blocks_map);
}

static int __init sswap_dram_init_module(void)
{
	int i;
	uint64_t idx;
	pr_info("start: %s\n", __FUNCTION__);
	pr_info("will use new DRAM backend");

	drambuf = vzalloc(REMOTE_BUF_SIZE + (1 << PAGE_SHIFT));
    local_partition_start = (void*)(((uint64_t)drambuf + RBLOCK_SIZE - 1) & ~(RBLOCK_SIZE - 1));
	pr_info("vzalloc'ed %lu bytes for dram backend\n", REMOTE_BUF_SIZE);

    global_block_queue = (struct GlobalBlockQueue*) vzalloc(sizeof(struct GlobalBlockQueue));
	if(!global_block_queue) {
		pr_err("Bad vzalloc for global_block_queue.\n");
	}
	//spin_lock_init(&global_block_queue->lock);
    atomic64_set(&global_block_queue->begin, 0);
    atomic64_set(&global_block_queue->end, 0);
    for(idx = 0;idx < TOTAL_BLOCKS; ++idx) {
      atomic64_set(&global_block_queue->pages[idx], 0);
    }

	idx = 1;
    while(get_length_queue() < TOTAL_BLOCKS - 10) {
      push_queue((uint64_t)local_partition_start + (idx * RBLOCK_SIZE));
      idx++;
    }

    blocks_map = vzalloc(sizeof(struct rhashtable));
    if (!blocks_map) {
        pr_err("alloc memory for blocks_map failed\n");
        return -1;
    }
    rhashtable_init(blocks_map, &blocks_map_params);
    pr_info("blocks_map init successfully.\n");

	for(i = 0;i < NUM_FREE_BLOCKS_LIST; ++i) {
		spin_lock_init(&free_blocks_list_locks[i]);
        INIT_LIST_HEAD(&free_blocks_lists[i]);
	}
	pr_info("free_blocks_trees init successfully.\n");

    spin_lock_init(&global_lock);

	timer_setup(&gc_timer, gc_timer_callback, 0);
    mod_timer(&gc_timer, jiffies + msecs_to_jiffies(GC_INTERVAL));

	timer_setup(&swap_pages_timer, swap_pages_timer_callback, 0);
    mod_timer(&swap_pages_timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL));


	pr_info("DRAM backend is ready for reqs\n");
	return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
