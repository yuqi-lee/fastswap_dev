#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/list.h>

#define addr_space (1024 * 1024 * 1024 * 32l)
#define block_size (4 * 1024 * 1024)
#define max_block_num (addr_space / block_size)

struct rdma_addr{
    uint64_t addr;
    uint32_t rkey;
};

struct cpu_cache_storage {
    u64 block_size;
    struct rdma_addr items[nprocs][max_alloc_item];
    u64 free_items[nprocs][max_free_item];
    struct rdma_addr class_items[class_num][max_alloc_item];
    u64 class_free_items[class_num][max_free_item];

    u32 reader[nprocs];
    u32 class_reader[class_num];
    u32 free_reader[nprocs];
    u32 class_free_reader[nprocs];

    u32 writer[nprocs];
    u32 class_writer[class_num];
    u32 free_writer[nprocs];
    u32 class_free_writer[nprocs];
};

struct block_info{
    u64 raddr;
    u32 rkey;
    spinlock lock;
    u16 cnt;

    DECLARE_BITMAP(rpages, (block_size >> PAGE_SHIFT));
    struct list_head block_list;
};

struct block_info *blocks = NULL;
spinlock_t blocks_lock;
struct cpu_cache_storage *cpu_cache_ = NULL;

int cpu_cache_init(void);

int add_remote_block(void);
void delete_remote_block(u64 raddr);
u64 alloc_remote_page(void);
void free_remote_page(u64 raddr);
u32 get_rkey(u64 raddr);