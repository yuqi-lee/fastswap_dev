#if !defined(_SSWAP_RDMA_H)
#define _SSWAP_RDMA_H

#include "../msg.h"
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <linux/bitmap.h>
#include <linux/rhashtable.h>
#include <linux/rbtree.h>

#define RBLOCK_SIZE (2UL*1024*1024)
#define BLOCK_SHIFT 21
#define NUM_FREE_BLOCKS_TREE 1
#define TOTAL_BLOCKS (16UL *  1024)
#define TOTAL_PAGES (8UL*1024*1024)
#define INFO_PRINT_TINTERVAL 1000

#define TIME_NOW (ktime_get_ns())
#define TIME_DURATION_US(START, END) \
    ((long)((END) - (START)) / 1000)

const uint64_t num_pages_total = TOTAL_PAGES;

enum qp_type {
  QP_READ_SYNC,
  QP_READ_ASYNC,
  QP_WRITE_SYNC
};

struct sswap_rdma_dev {
  struct ib_device *dev;
  struct ib_pd *pd;
};

struct rdma_req {
  struct completion done;
  struct list_head list;
  struct ib_cqe cqe;
  u64 dma;
  struct page *page;
};

struct sswap_rdma_ctrl;

struct rdma_queue {
  struct ib_qp *qp;
  struct ib_cq *cq;
  spinlock_t cq_lock;
  enum qp_type qp_type;

  struct sswap_rdma_ctrl *ctrl;

  struct rdma_cm_id *cm_id;
  int cm_error;
  struct completion cm_done;

  atomic_t pending;
};

struct two_sided_rdma_send {
	struct ib_cqe cqe;
	struct ib_send_wr sq_wr;
	struct ib_sge send_sgl;
	struct message *send_buf;
	u64 send_dma_addr;

	struct queue *q;
};

struct two_sided_rdma_recv {
	struct ib_cqe cqe;
	struct ib_recv_wr rq_wr;
	struct ib_sge recv_sgl;
	struct message *recv_buf;
	u64 recv_dma_addr;

	struct queue *q;
};

struct sswap_rdma_ctrl {
  struct sswap_rdma_dev *rdev; // TODO: move this to queue
  struct rdma_queue *queues;

  struct two_sided_rdma_recv rdma_recv_req;
	struct two_sided_rdma_send rdma_send_req;

  union {
    struct sockaddr addr;
    struct sockaddr_in addr_in;
  };

  union {
    struct sockaddr srcaddr;
    struct sockaddr_in srcaddr_in;
  };
};

struct block_info {
    uint64_t raddr;
    uint32_t rkey;
    spinlock_t block_lock;
    uint16_t cnt;
    uint32_t free_tree_idx;
    DECLARE_BITMAP(rpages_bitmap, (RBLOCK_SIZE >> PAGE_SHIFT));

    struct rhash_head block_node_rhash;
    //struct list_head block_node_list;
    struct rb_node block_node_rbtree; 
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
struct rb_root free_blocks_trees[NUM_FREE_BLOCKS_TREE];
spinlock_t free_blocks_tree_locks[NUM_FREE_BLOCKS_TREE];
spinlock_t global_lock;

struct timer_list swap_pages_timer;
struct timer_list gc_timer;

atomic64_t num_swap_pages = ATOMIC64_INIT(0);
atomic64_t num_alloc_blocks = ATOMIC64_INIT(0);
atomic64_t num_free_blocks = ATOMIC64_INIT(0);
atomic64_t num_free_fail = ATOMIC64_INIT(0);

uint64_t offset_to_rpage_addr[TOTAL_PAGES] = {0};


struct rdma_queue *sswap_rdma_get_queue(unsigned int idx, enum qp_type type);
enum qp_type get_queue_type(unsigned int idx);
int sswap_rdma_read_async(struct page *page, u64 roffset);
int sswap_rdma_read_sync(struct page *page, u64 roffset);
int sswap_rdma_write(struct page *page, u64 roffset);
int sswap_rdma_poll_load(int cpu);
void sswap_rdma_free_page(u64 roffset);

void setup_message_wr(struct sswap_rdma_ctrl *ctrl);
int setup_rdma_ctrl_comm_buffer(struct sswap_rdma_ctrl *ctrl);
int setup_buffers(struct sswap_rdma_ctrl *ctrl);


int alloc_remote_block(uint32_t free_list_idx);
void free_remote_block(struct block_info *bi);
uint64_t alloc_remote_page(void);
void free_remote_page(uint64_t raddr);
uint32_t get_rkey(uint64_t raddr);
bool compare_blocks(struct rb_node *n1, const struct rb_node *n2);

#endif
