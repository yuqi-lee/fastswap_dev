#if !defined(_SSWAP_DRAM_H)
#define _SSWAP_DRAM_H

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/bitmap.h>
#include <linux/rhashtable.h>
#include <linux/list.h>

#define RBLOCK_SIZE (2UL*1024*1024)
#define BLOCK_SHIFT 21
#define NUM_FREE_BLOCKS_LIST 1
#define TOTAL_BLOCKS (16UL *  1024)
#define TOTAL_PAGES (8UL*1024*1024)


struct block_info {
    uint64_t raddr;
    uint32_t rkey;
    spinlock_t block_lock;
    uint16_t cnt;
    uint32_t free_list_idx;
    DECLARE_BITMAP(rpages_bitmap, (RBLOCK_SIZE >> PAGE_SHIFT));

    struct rhash_head block_node_rhash;
    struct list_head block_node_list;
    //struct rb_node block_node_rbtree; 
};

struct rhashtable_params blocks_map_params = {
    .head_offset = offsetof(struct block_info, block_node_rhash),
    .key_offset = offsetof(struct block_info, raddr),
    .key_len = sizeof(((struct block_info *)0)->raddr),
    .hashfn = jhash,
    // .nulls_base = (1U << RHT_BASE_SHIFT), 
    // not support in kernel 5.15
};

struct rhashtable *blocks_map = NULL;
struct list_head free_blocks_lists[NUM_FREE_BLOCKS_LIST];
spinlock_t free_blocks_list_locks[NUM_FREE_BLOCKS_LIST];
spinlock_t global_lock;

struct timer_list swap_pages_timer;
struct timer_list gc_timer;

atomic64_t num_swap_pages = ATOMIC64_INIT(0);
atomic64_t num_alloc_blocks = ATOMIC64_INIT(0);
atomic64_t num_free_blocks = ATOMIC64_INIT(0);
atomic64_t num_free_fail = ATOMIC64_INIT(0);

uint64_t offset_to_rpage_addr[TOTAL_PAGES] = {0};


int sswap_rdma_read_async(struct page *page, u64 roffset);
int sswap_rdma_read_sync(struct page *page, u64 roffset);
int sswap_rdma_write(struct page *page, u64 roffset);
int sswap_rdma_poll_load(int cpu);
int sswap_rdma_drain_loads_sync(int cpu, int target);
void sswap_rdma_free_page(uint64_t roffset);

bool compare_blocks(struct rb_node *n1, const struct rb_node *n2);

int alloc_remote_block(uint32_t free_list_idx);
void free_remote_block(struct block_info *bi);
uint64_t alloc_remote_page(void);
void free_remote_page(uint64_t raddr);
uint32_t get_rkey(uint64_t raddr);

#endif
