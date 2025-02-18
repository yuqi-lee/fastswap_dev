#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/time.h>
#include "fastswap_dram.h"
#include <linux/delay.h>
#include <linux/kthread.h>

#define ONEGB (1024UL*1024*1024)
#define REMOTE_BUF_SIZE (ONEGB * 33) /* must match what server is allocating */
#define NUM_ONLINE_CPUS 128
#define GC_INTERVAL 500
#define INFO_PRINT_TINTERVAL 1000
#define RECYCLE_TINTERVAL 100
#define MB_SHIFT 20

#define RECYCLE_DAEMON_CORE 40

static void *drambuf;
static void *local_partition_start;
//static struct task_struct *thread_recycle;

struct GlobalBlockQueue {
    atomic64_t begin;
    atomic64_t end;
	//spinlock_t lock;
    atomic64_t pages[TOTAL_BLOCKS];
};

static struct GlobalBlockQueue* global_block_queue = NULL;
static struct GlobalBlockQueue* recycle_block_queue = NULL;

uint64_t get_length_queue(struct GlobalBlockQueue* q) {
    uint64_t begin = atomic64_read(&q->begin);
    uint64_t end = atomic64_read(&q->end);
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (TOTAL_BLOCKS - begin + end);
    }
}

uint64_t pop_queue(struct GlobalBlockQueue* q) {
    uint64_t ret = 0;
    uint64_t prev_begin;

	//spin_lock(&global_block_queue->lock);

    while(get_length_queue(q) == 0) ;
    prev_begin = atomic64_read(&q->begin);
    atomic64_set(&q->begin, (prev_begin + 1) % TOTAL_BLOCKS);
    while(atomic64_read(&q->pages[prev_begin]) == 0) ;
    ret = atomic64_read(&q->pages[prev_begin]);
    atomic64_set(&q->pages[prev_begin], 0);
    //pr_info("pop_queue_allocator success.\n");
	//spin_unlock(&global_block_queue->lock);

    return ret;
}

int push_queue(uint64_t page_addr, struct GlobalBlockQueue* q) {
    uint64_t prev_end;

    //spin_lock(&global_block_queue->lock);
    prev_end = atomic64_read(&q->end);

    while (get_length_queue(q) >= TOTAL_BLOCKS - 1) ;
    atomic64_set(&q->end, (prev_end + 1) % TOTAL_BLOCKS);
    atomic64_set(&q->pages[prev_end], page_addr);
	//spin_unlock(&global_block_queue->lock);
    return 0;
}


bool compare_blocks(struct rb_node *n1, const struct rb_node *n2) {
    struct block_info *block1 = rb_entry(n1, struct block_info, block_node_rbtree);
    struct block_info *block2 = rb_entry(n2, struct block_info, block_node_rbtree);
    
	return block1->cnt < block2->cnt;
}

// must obtain free_blocks_tree_lock when excute this function
void free_remote_block(struct block_info *bi) {
	BUG_ON(bi->free_tree_idx >= NUM_FREE_BLOCKS_TREE);
    rb_erase(&bi->block_node_rbtree, &free_blocks_trees[bi->free_tree_idx]);
    rhashtable_remove_fast(blocks_map, &bi->block_node_rhash, blocks_map_params);

    //add_free_cache(bi->raddr/*, bi->rkey*/);

    udelay(8);
    BUG_ON((bi->raddr & ((1 << BLOCK_SHIFT) - 1)) != 0);
	push_queue(bi->raddr, recycle_block_queue);
    kfree(bi);

    atomic64_inc(&num_free_blocks);
}
EXPORT_SYMBOL(free_remote_block);

void free_remote_page(uint64_t raddr) {
    struct block_info *bi = NULL;
    uint64_t raddr_block; 
    uint64_t offset; 
    uint32_t nproc = raw_smp_processor_id();
    uint32_t free_tree_idx = nproc % NUM_FREE_BLOCKS_TREE;
    //uint32_t count = 0;
    
    BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
    spin_lock(&free_blocks_tree_locks[free_tree_idx]);

    raddr_block = raddr >> BLOCK_SHIFT;
    raddr_block = raddr_block << BLOCK_SHIFT;
    bi = rhashtable_lookup_fast(blocks_map, &raddr_block, blocks_map_params);
    if(!bi) {
        pr_err("the page being free(%p) is not exit: cannot find out block_info.\n", (void*)raddr);
        //spin_unlock(&global_lock);
        spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
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
		BUG_ON(bi->free_tree_idx != NUM_FREE_BLOCKS_TREE);

        bi->free_tree_idx = free_tree_idx;
	} else {
		BUG_ON(bi->free_tree_idx >= NUM_FREE_BLOCKS_TREE);

		rb_erase(&bi->block_node_rbtree, &free_blocks_trees[bi->free_tree_idx]);
		//bi->free_tree_idx = free_tree_idx;
	}
    bi->cnt += 1;
	rb_add(&bi->block_node_rbtree, &free_blocks_trees[free_tree_idx], compare_blocks);

    //spin_unlock(&bi->block_lock);
    spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
    //spin_unlock(&global_lock);
}
EXPORT_SYMBOL(free_remote_page);

// must obtain "free_blocks_tree_lock" when excute this function
int alloc_remote_block(uint32_t free_tree_idx) {
    struct block_info *bi;
    uint64_t raddr_ = 0;
    uint32_t rkey_ = 0;

    udelay(8);
    raddr_ = pop_queue(global_block_queue);
    BUG_ON((raddr_ & ((1 << BLOCK_SHIFT) - 1)) != 0);
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
    bi->free_tree_idx = free_tree_idx;
    spin_lock_init(&bi->block_lock);
    bitmap_zero(bi->rpages_bitmap, RBLOCK_SIZE >> PAGE_SHIFT);
    //INIT_LIST_HEAD();
	rb_add(&bi->block_node_rbtree, &free_blocks_trees[free_tree_idx], compare_blocks);

    // insert to rhashtable (blocks_map)
    rhashtable_insert_fast(blocks_map, &bi->block_node_rhash, blocks_map_params);

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
    uint32_t free_tree_idx = nproc % NUM_FREE_BLOCKS_TREE;
    //uint32_t raw_free_tree_idx = free_tree_idx;
    //uint8_t locked = 0;
	struct rb_node *first_node;

    //spin_lock(&global_lock);
    spin_lock(&free_blocks_tree_locks[free_tree_idx]);

    if(RB_EMPTY_ROOT(&free_blocks_trees[free_tree_idx])) {
        ret = alloc_remote_block(free_tree_idx);
        if(ret) {
            pr_err("can not alloc remote block.\n");
            spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
            //spin_unlock(&global_lock);
            return 0;
        }
    }

    first_node = rb_first(&free_blocks_trees[free_tree_idx]);
	if(!first_node) {
		pr_err("fail to add new block to free_blocks_list\n");
        spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
        //spin_unlock(&global_lock);
        return 0;
	}
	
    bi = rb_entry(first_node, struct block_info, block_node_rbtree);

    //BUG_ON(bi->free_list_idx != free_list_idx);
    if(bi->free_tree_idx != free_tree_idx) {
        pr_err("block_info's free_tree_idx error: 2\n");
    }

    //spin_lock(&bi->block_lock);
    offset = find_first_zero_bit(bi->rpages_bitmap, RBLOCK_SIZE >> PAGE_SHIFT);
    BUG_ON(offset >= (RBLOCK_SIZE >> PAGE_SHIFT));
    set_bit(offset, bi->rpages_bitmap);
    
    bi->cnt -= 1;
    BUG_ON(bi->cnt > (RBLOCK_SIZE >> PAGE_SHIFT));

    if(bi->cnt == 0) {
        rb_erase(&bi->block_node_rbtree, &free_blocks_trees[free_tree_idx]);
        bi->free_tree_idx = NUM_FREE_BLOCKS_TREE;
    }
    //spin_unlock(&global_lock);
    spin_unlock(&free_blocks_tree_locks[free_tree_idx]);

    raddr = bi->raddr + (offset << PAGE_SHIFT);
    return raddr;
}
EXPORT_SYMBOL(alloc_remote_page);


int sswap_rdma_write(struct page *page, u64 roffset)
{
  	uint64_t raddr = offset_to_rpage_addr[roffset];
	void *page_vaddr;
    udelay(6);


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
    udelay(6);


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

void recycle_timer_callback(struct timer_list *timer) {
  uint32_t count = 0;
  uint64_t addr;
  //set_cpus_allowed_ptr(current, cpumask_of(RECYCLE_DAEMON_CORE));
  
  while(get_length_queue(recycle_block_queue)) {
    addr = pop_queue(recycle_block_queue);
    udelay(30);
    push_queue(addr, global_block_queue);
    count++;
  }

  if(count > 0)
    pr_info("recycle %d remote blocks.", count);

  mod_timer(timer, jiffies + msecs_to_jiffies(RECYCLE_TINTERVAL)); 
}

void gc_timer_callback(struct timer_list *timer) {
  struct block_info *bi;  
  struct rb_node *cur_node;
  int i;

  for(i = 0;i < NUM_FREE_BLOCKS_TREE; ++i) {
    //if(spin_trylock(&free_blocks_tree_locks[i])) {
    //spin_lock(&global_lock);
    spin_lock(&free_blocks_tree_locks[i]);
	cur_node = rb_last(&free_blocks_trees[i]);
    while(cur_node) {
		bi = rb_entry(cur_node, struct block_info, block_node_rbtree);
        cur_node = rb_prev(cur_node); 
        //spin_lock(&bi->block_lock);
        BUG_ON(bi->free_tree_idx != i);
        if(bi->cnt < (RBLOCK_SIZE >> PAGE_SHIFT)) {   
			//spin_unlock(&bi->block_lock);
            break;
        }
		free_remote_block(bi);
    }
    spin_unlock(&free_blocks_tree_locks[i]);
    //spin_unlock(&global_lock);
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

    /*init global_block_queue*/
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
    while(get_length_queue(global_block_queue) < TOTAL_BLOCKS - 10) {
      push_queue((uint64_t)local_partition_start + (idx * RBLOCK_SIZE), global_block_queue);
      idx++;
    }

    /*init recycle_block_queue*/
    recycle_block_queue = (struct GlobalBlockQueue*) vzalloc(sizeof(struct GlobalBlockQueue));
	if(!recycle_block_queue) {
		pr_err("Bad vzalloc for recycle_block_queue.\n");
	}
	//spin_lock_init(&global_block_queue->lock);
    atomic64_set(&recycle_block_queue->begin, 0);
    atomic64_set(&recycle_block_queue->end, 0);
    for(idx = 0;idx < TOTAL_BLOCKS; ++idx) {
      atomic64_set(&recycle_block_queue->pages[idx], 0);
    }

    blocks_map = vzalloc(sizeof(struct rhashtable));
    if (!blocks_map) {
        pr_err("alloc memory for blocks_map failed\n");
        return -1;
    }
    rhashtable_init(blocks_map, &blocks_map_params);
    pr_info("blocks_map init successfully.\n");

	for(i = 0;i < NUM_FREE_BLOCKS_TREE; ++i) {
		spin_lock_init(&free_blocks_tree_locks[i]);
		free_blocks_trees[i] = RB_ROOT;
	}
	pr_info("free_blocks_trees init successfully.\n");

    //spin_lock_init(&global_lock);

	timer_setup(&gc_timer, gc_timer_callback, 0);
    mod_timer(&gc_timer, jiffies + msecs_to_jiffies(GC_INTERVAL));

	timer_setup(&swap_pages_timer, swap_pages_timer_callback, 0);
    mod_timer(&swap_pages_timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL));

    timer_setup(&recycle_timer, recycle_timer_callback, 0);
    mod_timer(&recycle_timer, jiffies + msecs_to_jiffies(RECYCLE_TINTERVAL));

	pr_info("DRAM backend is ready for reqs\n");
	return 0;
}

module_init(sswap_dram_init_module);
module_exit(sswap_dram_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DRAM backend");
