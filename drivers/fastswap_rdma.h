#if !defined(_SSWAP_RDMA_H)
#define _SSWAP_RDMA_H

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
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/directswap.h>
#include "rpage_allocator.h"
#include "extended_entry_allocator.h"

#define num_groups 8
// #define print_interval (256 * 1024)
#define num_pages_total  (addr_space >> PAGE_SHIFT)
#define swap_pages_print_interval 2000

extern atomic_t num_alloc_blocks;
extern atomic_t num_free_blocks;
extern atomic_t num_free_fail;

extern struct allocator_page_queues *queues_allocator;
extern struct deallocator_page_queues *queues_deallocator;

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

struct sswap_rdma_memregion {
    u64 baseaddr;
    u32 key;
};

struct sswap_rdma_ctrl {
  struct sswap_rdma_dev *rdev; // TODO: move this to queue
  struct rdma_queue *queues;
  struct sswap_rdma_memregion servermr;

  union {
    struct sockaddr addr;
    struct sockaddr_in addr_in;
  };

  union {
    struct sockaddr srcaddr;
    struct sockaddr_in srcaddr_in;
  };
};

struct timer_list swap_pages_timer;
//atomic_t num_direct_swap_pages = ATOMIC_INIT(0);
atomic_t num_direct_swapout_pages_done = ATOMIC_INIT(0);
atomic_t num_direct_swapin_pages_done = ATOMIC_INIT(0);
atomic64_t num_kfifo_daemon_loops = ATOMIC64_INIT(0);

atomic_t num_swap_pages = ATOMIC_INIT(0);
spinlock_t locks[num_groups];
u64 offset_to_rpage_addr[num_pages_total] = {0};
u64 *base_address;
u32 *remote_keys;
//struct kfifo central_heap;
DECLARE_KFIFO(my_fifo, unsigned char, 1024);
char central_heap[num_pages_total] = {'F'};

struct rdma_queue *sswap_rdma_get_queue(unsigned int idx, enum qp_type type);
enum qp_type get_queue_type(unsigned int idx);
int sswap_rdma_read_async(struct page *page, u64 roffset);
int sswap_rdma_read_sync(struct page *page, u64 roffset);
int sswap_rdma_write(struct page *page, u64 roffset);
int direct_swap_rdma_read_async(struct page *page, u64 roffset, int type);
int direct_swap_rdma_read_sync(struct page *page, u64 roffset, int type);
int direct_swap_rdma_write(struct page *page, u64 roffset, int type);
int sswap_rdma_poll_load(int cpu);
void sswap_rdma_free_page(u64 roffset);

#endif
