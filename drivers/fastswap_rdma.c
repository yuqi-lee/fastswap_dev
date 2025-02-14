#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "fastswap_rdma.h"
#include <linux/slab.h>
#include <linux/cpumask.h> 
#include <linux/delay.h>

static struct sswap_rdma_ctrl *gctrl;
static int serverport;
static int numqueues;
static int rpc_queue_id;
static int numcpus;
static char serverip[INET_ADDRSTRLEN];
static char clientip[INET_ADDRSTRLEN];
static struct kmem_cache *req_cache;
module_param_named(sport, serverport, int, 0644);
module_param_named(nq, numqueues, int, 0644);
module_param_string(sip, serverip, INET_ADDRSTRLEN, 0644);
module_param_string(cip, clientip, INET_ADDRSTRLEN, 0644);

// TODO: destroy ctrl

#define CONNECTION_TIMEOUT_MS 60000
#define QP_QUEUE_DEPTH 256
/* we don't really use recv wrs, so any small number should do */
#define QP_MAX_RECV_WR 4
/* we mainly do send wrs */
#define QP_MAX_SEND_WR	(4096)
#define CQ_NUM_CQES	(QP_MAX_SEND_WR)
#define POLL_BATCH_HIGH (QP_MAX_SEND_WR / 4)
#define RDMA_TIMEOUT_US 1000000 // 1s


int send_message_to_remote(int message_type)
{
	int ret = 0;
	//const struct ib_recv_wr *recv_bad_wr;
	const struct ib_send_wr *send_bad_wr;
	struct rdma_queue *q;
  uint64_t start;
  struct ib_wc wc;
  int rc;

	q = &(gctrl->queues[rpc_queue_id]);
	gctrl->rdma_send_req.send_buf->type = message_type;

  /*
	// post a 2-sided RDMA recv wr first.
	ret = ib_post_recv(q->qp, &gctrl->rdma_recv_req.rq_wr,
			   &recv_bad_wr);
	if (ret) {
		pr_err("%s, Post 2-sided message to receive data failed.\n",
		       __func__);
		return ret;
	}*/

	pr_debug("Send a Message to memory server. Message type is : %d \n", message_type);
	ret = ib_post_send(q->qp, &gctrl->rdma_send_req.sq_wr,
			   &send_bad_wr);
	if (ret) {
		pr_err("%s: BIND_SINGLE MSG send error %d\n", __func__, ret);
    return ret;
	}

  start = TIME_NOW;
  ret = -1;
  while (true) {
    if (TIME_DURATION_US(start, TIME_NOW) > RDMA_TIMEOUT_US) {
      pr_err("rdma_remote_write timeout\n");
      return -1;
    }
    rc = ib_poll_cq(q->cq, 1, &wc);
    if (rc > 0) {
      if (IB_WC_SUCCESS == wc.status) {
        // Break out as operation completed successfully
        // printf("Break out as operation completed successfully\n");
        ret = 0;
        break;
      } else if (IB_WC_WR_FLUSH_ERR == wc.status) {
        pr_err("cmd_send IBV_WC_WR_FLUSH_ERR");
        break;
      } else if (IB_WC_RNR_RETRY_EXC_ERR == wc.status) {
        pr_err("cmd_send IBV_WC_RNR_RETRY_EXC_ERR");
        break;
      } else {
        pr_err("cmd_send ibv_poll_cq status error");
        break;
      }
    } else if (0 == rc) {
      continue;
    } else {
      pr_err("ib_poll_cq fail");
      break;
    }
  }

	return ret;
}


int rdma_alloc_remote_block(uint64_t *addr, uint32_t *rkey) {
  int ret = 0;
	struct rdma_queue *q;
  uint64_t start;

  gctrl->rdma_recv_req.recv_buf->status = IDLE;
  gctrl->rdma_send_req.send_buf->status = WORK;
	q = &(gctrl->queues[rpc_queue_id]);
	ret = send_message_to_remote(ALLOCATE_BLOCK);
	if (ret) {
		pr_err("%s, Post 2-sided message to remote server failed.\n",
		       __func__);
	}

  while(gctrl->rdma_recv_req.recv_buf->status == IDLE) {
    if (TIME_DURATION_US(start, TIME_NOW) > RDMA_TIMEOUT_US) {
      pr_err("wait for request completion timeout: allocate_remote_page.\n");
      return -1;
    }
  }

  *addr = gctrl->rdma_recv_req.recv_buf->addr;
  *rkey = gctrl->rdma_recv_req.recv_buf->addr;
  
  return 0;
}

int rdma_free_remote_block(uint64_t addr, uint32_t rkey) {
  int ret = 0;
	struct rdma_queue *q;
  //uint64_t start;

  gctrl->rdma_recv_req.recv_buf->status = IDLE;
  gctrl->rdma_send_req.send_buf->addr = addr;
  gctrl->rdma_send_req.send_buf->rkey = rkey;
	q = &(gctrl->queues[rpc_queue_id]);
	ret = send_message_to_remote(FREE_BLOCK);
	if (ret) {
		pr_err("%s, Post 2-sided message to remote server failed.\n",
		       __func__);
	}

  /*
  while(gctrl->rdma_recv_req.recv_buf->status == IDLE) {
    if (TIME_DURATION_US(start, TIME_NOW) > RDMA_TIMEOUT_US) {
      pr_err("wait for request completion timeout: allocate_remote_page.\n");
      return -1;
    }
  }

  *addr = (struct message*)gctrl->rdma_recv_req.recv_buf->addr;
  *rkey = (struct message*)gctrl->rdma_send_req.recv_buf->addr;*/
  
  return 0;
}

// must obtain free_blocks_tree_lock when excute this function
void free_remote_block(struct block_info *bi) {
	BUG_ON(bi->free_tree_idx >= NUM_FREE_BLOCKS_TREE);
    rb_erase(&bi->block_node_rbtree, &free_blocks_trees[bi->free_tree_idx]);
    rhashtable_remove_fast(blocks_map, &bi->block_node_rhash, blocks_map_params);

    //add_free_cache(bi->raddr/*, bi->rkey*/);
	  //push_queue(bi->raddr);
    rdma_free_remote_block(bi->raddr, bi->rkey);
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
    //spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
    spin_unlock(&global_lock);
}
EXPORT_SYMBOL(free_remote_page);

// must obtain "free_blocks_tree_lock" when excute this function
int alloc_remote_block(uint32_t free_tree_idx) {
    struct block_info *bi;
    uint64_t raddr_ = 0;
    uint32_t rkey_ = 0;

    //raddr_ = pop_queue();
    rdma_alloc_remote_block(&raddr_, &rkey_);
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

bool compare_blocks(struct rb_node *n1, const struct rb_node *n2) {
    struct block_info *block1 = rb_entry(n1, struct block_info, block_node_rbtree);
    struct block_info *block2 = rb_entry(n2, struct block_info, block_node_rbtree);
    
	return block1->cnt < block2->cnt;
}

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

    spin_lock(&global_lock);

    if(RB_EMPTY_ROOT(&free_blocks_trees[free_tree_idx])) {
        ret = alloc_remote_block(free_tree_idx);
        if(ret) {
            pr_err("can not alloc remote block.\n");
            //spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
            spin_unlock(&global_lock);
            return 0;
        }
    }

    first_node = rb_first(&free_blocks_trees[free_tree_idx]);
	if(!first_node) {
		pr_err("fail to add new block to free_blocks_list\n");
        //spin_unlock(&free_blocks_tree_locks[free_tree_idx]);
        spin_unlock(&global_lock);
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
    spin_unlock(&global_lock);

    raddr = bi->raddr + (offset << PAGE_SHIFT);
    return raddr;
}
EXPORT_SYMBOL(alloc_remote_page);


static int sswap_rdma_addone(struct ib_device *dev)
{
  pr_info("sswap_rdma_addone() = %s\n", dev->name);
  return 0;
  // TODO
}

static void sswap_rdma_removeone(struct ib_device *ib_device, void *client_data)
{
  pr_info("sswap_rdma_removeone()\n");
}

static struct ib_client sswap_rdma_ib_client = {
  .name   = "sswap_rdma",
  .add    = sswap_rdma_addone,
  .remove = sswap_rdma_removeone
};

void setup_message_wr(struct sswap_rdma_ctrl *ctrl)
{
	ctrl->rdma_recv_req.recv_sgl.addr =
		ctrl->rdma_recv_req.recv_dma_addr;
	ctrl->rdma_recv_req.recv_sgl.length = sizeof(struct message);
	ctrl->rdma_recv_req.recv_sgl.lkey =
		ctrl->rdev->dev->local_dma_lkey;

	ctrl->rdma_recv_req.rq_wr.sg_list =
		&(ctrl->rdma_recv_req.recv_sgl);
	ctrl->rdma_recv_req.rq_wr.num_sge = 1;
	//ctrl->rdma_recv_req.cqe.done = two_sided_message_done;
	ctrl->rdma_recv_req.rq_wr.wr_cqe =
		&(ctrl->rdma_recv_req.cqe);

	ctrl->rdma_send_req.send_sgl.addr =
		ctrl->rdma_send_req.send_dma_addr;
	ctrl->rdma_send_req.send_sgl.length = sizeof(struct message);
	ctrl->rdma_send_req.send_sgl.lkey =
		ctrl->rdev->dev->local_dma_lkey;

	ctrl->rdma_send_req.sq_wr.opcode = IB_WR_SEND;
	ctrl->rdma_send_req.sq_wr.send_flags = IB_SEND_SIGNALED;
	ctrl->rdma_send_req.sq_wr.sg_list =
		&ctrl->rdma_send_req.send_sgl;
	ctrl->rdma_send_req.sq_wr.num_sge = 1;
	//ctrl->rdma_send_req.cqe.done = two_sided_message_done;
	ctrl->rdma_send_req.sq_wr.wr_cqe =
		&(ctrl->rdma_send_req.cqe);

	return;
}


static struct sswap_rdma_dev *sswap_rdma_get_device(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev = NULL;

  if (!q->ctrl->rdev) {
    rdev = kzalloc(sizeof(*rdev), GFP_KERNEL);
    if (!rdev) {
      pr_err("no memory\n");
      goto out_err;
    }

    rdev->dev = q->cm_id->device;

    pr_info("selecting device %s\n", rdev->dev->name);

    rdev->pd = ib_alloc_pd(rdev->dev, 0);
    if (IS_ERR(rdev->pd)) {
      pr_err("ib_alloc_pd\n");
      goto out_free_dev;
    }

    if (!(rdev->dev->attrs.device_cap_flags &
          IB_DEVICE_MEM_MGT_EXTENSIONS)) {
      pr_err("memory registrations not supported\n");
      goto out_free_pd;
    }

    q->ctrl->rdev = rdev;

    setup_rdma_ctrl_comm_buffer(q->ctrl);
  }

  return q->ctrl->rdev;

out_free_pd:
  ib_dealloc_pd(rdev->pd);
out_free_dev:
  kfree(rdev);
out_err:
  return NULL;
}

int setup_rdma_ctrl_comm_buffer(struct sswap_rdma_ctrl *ctrl)
{
	int ret = 0;

	if (ctrl->rdev == NULL) {
		pr_err("%s, ctrl->rdev is NULL. too early to regiseter RDMA buffer.\n",
		       __func__);
		goto err;
	}

	ret = setup_buffers(ctrl);
	if (unlikely(ret)) {
		pr_err("%s, Bind DMA buffer error\n", __func__);
		goto err;
	}

err:
	return ret;
}

u32 get_rkey(u64 raddr) {
    struct block_info *bi = NULL;
    
    BUG_ON((raddr & ((1 << BLOCK_SHIFT) - 1)) != 0);

    bi = rhashtable_lookup_fast(blocks_map, &raddr, blocks_map_params);
    if(!bi || bi->rkey == 0) {
        pr_err("cannot get rkey(with remote address:%p)\n", (void*)raddr);
        return 0;
    }
    return bi->rkey;
}
EXPORT_SYMBOL(get_rkey);


int setup_buffers(struct sswap_rdma_ctrl *ctrl)
{
	int ret = 0;
	ctrl->rdma_recv_req.recv_buf =
		kzalloc(sizeof(struct message), GFP_KERNEL);
	ctrl->rdma_send_req.send_buf =
		kzalloc(sizeof(struct message), GFP_KERNEL);

	ctrl->rdma_recv_req.recv_dma_addr =
		ib_dma_map_single(ctrl->rdev->dev,
				  ctrl->rdma_recv_req.recv_buf,
				  sizeof(struct message), DMA_BIDIRECTIONAL);
	ctrl->rdma_send_req.send_dma_addr =
		ib_dma_map_single(ctrl->rdev->dev,
				  ctrl->rdma_send_req.send_buf,
				  sizeof(struct message), DMA_BIDIRECTIONAL);

	pr_debug("%s, Got dma/bus address 0x%llx, for the recv_buf 0x%llx \n",
		 __func__,
		 (unsigned long long)ctrl->rdma_recv_req.recv_dma_addr,
		 (unsigned long long)ctrl->rdma_recv_req.recv_buf);
	pr_debug("%s, Got dma/bus address 0x%llx, for the send_buf 0x%llx \n",
		 __func__,
		 (unsigned long long)ctrl->rdma_send_req.send_dma_addr,
		 (unsigned long long)ctrl->rdma_send_req.send_buf);

	setup_message_wr(ctrl);
	pr_debug("%s, allocated & registered buffers...\n", __func__);
	pr_debug("%s is done. \n", __func__);

	return ret;
}

static void sswap_rdma_qp_event(struct ib_event *e, void *c)
{
  pr_info("sswap_rdma_qp_event\n");
}

static int sswap_rdma_create_qp(struct rdma_queue *queue)
{
  struct sswap_rdma_dev *rdev = queue->ctrl->rdev;
  struct ib_qp_init_attr init_attr;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  memset(&init_attr, 0, sizeof(init_attr));
  init_attr.event_handler = sswap_rdma_qp_event;
  init_attr.cap.max_send_wr = QP_MAX_SEND_WR;
  init_attr.cap.max_recv_wr = QP_MAX_RECV_WR;
  init_attr.cap.max_recv_sge = 1;
  init_attr.cap.max_send_sge = 1;
  init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
  init_attr.qp_type = IB_QPT_RC;
  init_attr.send_cq = queue->cq;
  init_attr.recv_cq = queue->cq;
  /* just to check if we are compiling against the right headers */
  init_attr.create_flags = 0;

  ret = rdma_create_qp(queue->cm_id, rdev->pd, &init_attr);
  if (ret) {
    pr_err("rdma_create_qp failed: %d\n", ret);
    return ret;
  }

  queue->qp = queue->cm_id->qp;
  return ret;
}

static void sswap_rdma_destroy_queue_ib(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev;
  struct ib_device *ibdev;

  pr_info("start: %s\n", __FUNCTION__);

  rdev = q->ctrl->rdev;
  ibdev = rdev->dev;
  //rdma_destroy_qp(q->ctrl->cm_id);
  ib_free_cq(q->cq);
}

static int sswap_rdma_create_queue_ib(struct rdma_queue *q)
{
  struct ib_device *ibdev = q->ctrl->rdev->dev;
  int ret;
  int comp_vector = 0;

  pr_info("start: %s\n", __FUNCTION__);

  if (q->qp_type == QP_READ_ASYNC)
    q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES,
      comp_vector, IB_POLL_SOFTIRQ);
  else
    q->cq = ib_alloc_cq(ibdev, q, CQ_NUM_CQES,
      comp_vector, IB_POLL_DIRECT);

  if (IS_ERR(q->cq)) {
    ret = PTR_ERR(q->cq);
    goto out_err;
  }

  ret = sswap_rdma_create_qp(q);
  if (ret)
    goto out_destroy_ib_cq;

  return 0;

out_destroy_ib_cq:
  ib_free_cq(q->cq);
out_err:
  return ret;
}

static int sswap_rdma_addr_resolved(struct rdma_queue *q)
{
  struct sswap_rdma_dev *rdev = NULL;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  rdev = sswap_rdma_get_device(q);
  if (!rdev) {
    pr_err("no device found\n");
    return -ENODEV;
  }

  ret = sswap_rdma_create_queue_ib(q);
  if (ret) {
    return ret;
  }

  ret = rdma_resolve_route(q->cm_id, CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_route failed\n");
    sswap_rdma_destroy_queue_ib(q);
  }

  return 0;
}

static int sswap_rdma_route_resolved(struct rdma_queue *q,
    struct rdma_conn_param *conn_params)
{
  struct rdma_conn_param param = {};
  int ret;

  param.qp_num = q->qp->qp_num;
  param.flow_control = 1;
  param.responder_resources = 16;
  param.initiator_depth = 16;
  param.retry_count = 7;
  param.rnr_retry_count = 7;

  pr_info("max_qp_rd_atom=%d max_qp_init_rd_atom=%d\n",
      q->ctrl->rdev->dev->attrs.max_qp_rd_atom,
      q->ctrl->rdev->dev->attrs.max_qp_init_rd_atom);

  ret = rdma_connect_locked(q->cm_id, &param);
  if (ret) {
    pr_err("rdma_connect failed (%d)\n", ret);
    sswap_rdma_destroy_queue_ib(q);
  }

  return 0;
}

static int sswap_rdma_conn_established(struct rdma_queue *q)
{
  pr_info("connection established\n");
  return 0;
}

static int sswap_rdma_cm_handler(struct rdma_cm_id *cm_id,
    struct rdma_cm_event *ev)
{
  struct rdma_queue *queue = cm_id->context;
  int cm_error = 0;

  pr_info("cm_handler msg: %s (%d) status %d id %p\n", rdma_event_msg(ev->event),
    ev->event, ev->status, cm_id);

  switch (ev->event) {
  case RDMA_CM_EVENT_ADDR_RESOLVED:
    cm_error = sswap_rdma_addr_resolved(queue);
    break;
  case RDMA_CM_EVENT_ROUTE_RESOLVED:
    cm_error = sswap_rdma_route_resolved(queue, &ev->param.conn);
    break;
  case RDMA_CM_EVENT_ESTABLISHED:
    queue->cm_error = sswap_rdma_conn_established(queue);
    /* complete cm_done regardless of success/failure */
    complete(&queue->cm_done);
    return 0;
  case RDMA_CM_EVENT_REJECTED:
    pr_err("connection rejected\n");
    break;
  case RDMA_CM_EVENT_ADDR_ERROR:
  case RDMA_CM_EVENT_ROUTE_ERROR:
  case RDMA_CM_EVENT_CONNECT_ERROR:
  case RDMA_CM_EVENT_UNREACHABLE:
    pr_err("CM error event %d\n", ev->event);
    cm_error = -ECONNRESET;
    break;
  case RDMA_CM_EVENT_DISCONNECTED:
  case RDMA_CM_EVENT_ADDR_CHANGE:
  case RDMA_CM_EVENT_TIMEWAIT_EXIT:
    pr_err("CM connection closed %d\n", ev->event);
    break;
  case RDMA_CM_EVENT_DEVICE_REMOVAL:
    /* device removal is handled via the ib_client API */
    break;
  default:
    pr_err("CM unexpected event: %d\n", ev->event);
    break;
  }

  if (cm_error) {
    queue->cm_error = cm_error;
    complete(&queue->cm_done);
  }

  return 0;
}

inline static int sswap_rdma_wait_for_cm(struct rdma_queue *queue)
{
  wait_for_completion_interruptible_timeout(&queue->cm_done,
    msecs_to_jiffies(CONNECTION_TIMEOUT_MS) + 1);
  return queue->cm_error;
}

static int sswap_rdma_init_queue(struct sswap_rdma_ctrl *ctrl,
    int idx)
{
  struct rdma_queue *queue;
  int ret;

  pr_info("start: %s\n", __FUNCTION__);

  queue = &ctrl->queues[idx];
  queue->ctrl = ctrl;
  init_completion(&queue->cm_done);
  atomic_set(&queue->pending, 0);
  spin_lock_init(&queue->cq_lock);
  queue->qp_type = get_queue_type(idx);

  queue->cm_id = rdma_create_id(&init_net, sswap_rdma_cm_handler, queue,
      RDMA_PS_TCP, IB_QPT_RC);
  if (IS_ERR(queue->cm_id)) {
    pr_err("failed to create cm id: %ld\n", PTR_ERR(queue->cm_id));
    return -ENODEV;
  }

  queue->cm_error = -ETIMEDOUT;

  ret = rdma_resolve_addr(queue->cm_id, &ctrl->srcaddr, &ctrl->addr,
      CONNECTION_TIMEOUT_MS);
  if (ret) {
    pr_err("rdma_resolve_addr failed: %d\n", ret);
    goto out_destroy_cm_id;
  }

  ret = sswap_rdma_wait_for_cm(queue);
  if (ret) {
    pr_err("sswap_rdma_wait_for_cm failed\n");
    goto out_destroy_cm_id;
  }

  return 0;

out_destroy_cm_id:
  rdma_destroy_id(queue->cm_id);
  return ret;
}

static void sswap_rdma_stop_queue(struct rdma_queue *q)
{
  rdma_disconnect(q->cm_id);
}

static void sswap_rdma_free_queue(struct rdma_queue *q)
{
  rdma_destroy_qp(q->cm_id);
  ib_free_cq(q->cq);
  rdma_destroy_id(q->cm_id);
}

static int sswap_rdma_init_queues(struct sswap_rdma_ctrl *ctrl)
{
  int ret, i;
  for (i = 0; i < numqueues; ++i) {
    ret = sswap_rdma_init_queue(ctrl, i);
    if (ret) {
      pr_err("failed to initialized queue: %d\n", i);
      goto out_free_queues;
    }
  }

  return 0;

out_free_queues:
  for (i--; i >= 0; i--) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }

  return ret;
}

static void sswap_rdma_stopandfree_queues(struct sswap_rdma_ctrl *ctrl)
{
  int i;
  for (i = 0; i < numqueues; ++i) {
    sswap_rdma_stop_queue(&ctrl->queues[i]);
    sswap_rdma_free_queue(&ctrl->queues[i]);
  }
}

static int sswap_rdma_parse_ipaddr(struct sockaddr_in *saddr, char *ip)
{
  u8 *addr = (u8 *)&saddr->sin_addr.s_addr;
  size_t buflen = strlen(ip);

  pr_info("start: %s\n", __FUNCTION__);

  if (buflen > INET_ADDRSTRLEN)
    return -EINVAL;
  if (in4_pton(ip, buflen, addr, '\0', NULL) == 0)
    return -EINVAL;
  saddr->sin_family = AF_INET;
  return 0;
}

static int sswap_rdma_create_ctrl(struct sswap_rdma_ctrl **c)
{
  int ret;
  struct sswap_rdma_ctrl *ctrl;
  pr_info("will try to connect to %s:%d\n", serverip, serverport);

  *c = kzalloc(sizeof(struct sswap_rdma_ctrl), GFP_KERNEL);
  if (!*c) {
    pr_err("no mem for ctrl\n");
    return -ENOMEM;
  }
  ctrl = *c;

  ctrl->queues = kzalloc(sizeof(struct rdma_queue) * numqueues, GFP_KERNEL);
  ret = sswap_rdma_parse_ipaddr(&(ctrl->addr_in), serverip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  ctrl->addr_in.sin_port = cpu_to_be16(serverport);

  ret = sswap_rdma_parse_ipaddr(&(ctrl->srcaddr_in), clientip);
  if (ret) {
    pr_err("sswap_rdma_parse_ipaddr failed: %d\n", ret);
    return -EINVAL;
  }
  /* no need to set the port on the srcaddr */

  return sswap_rdma_init_queues(ctrl);
}

static void __exit sswap_rdma_cleanup_module(void)
{
  sswap_rdma_stopandfree_queues(gctrl);
  ib_unregister_client(&sswap_rdma_ib_client);
  kfree(gctrl);
  gctrl = NULL;
  if (req_cache) {
    kmem_cache_destroy(req_cache);
  }

  del_timer(&swap_pages_timer);
}

static void sswap_rdma_write_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_write_done status is not success, it is=%d\n", wc->status);
    //q->write_error = wc->status;
  }
  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_TO_DEVICE);

  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
}

static void sswap_rdma_read_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *req =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS))
    pr_err("sswap_rdma_read_done status is not success, it is=%d\n", wc->status);

  ib_dma_unmap_page(ibdev, req->dma, PAGE_SIZE, DMA_FROM_DEVICE);

  SetPageUptodate(req->page);
  unlock_page(req->page);
  complete(&req->done);
  atomic_dec(&q->pending);
  kmem_cache_free(req_cache, req);
}

inline static int sswap_rdma_post_rdma(struct rdma_queue *q, struct rdma_req *qe,
  struct ib_sge *sge, u64 raddr, /*u32 rkey,*/enum ib_wr_opcode op)
{
  const struct ib_send_wr *bad_wr;
  struct ib_rdma_wr rdma_wr = {};
  int ret;
  //struct block_info *bi = NULL; 
  u64 raddr_block = raddr >> BLOCK_SHIFT;
  raddr_block = raddr_block << BLOCK_SHIFT;  

  BUG_ON(qe->dma == 0);
  BUG_ON(raddr == 0);
  BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);

  sge->addr = qe->dma;
  sge->length = PAGE_SIZE;
  sge->lkey = q->ctrl->rdev->pd->local_dma_lkey;

  /* TODO: add a chain of WR, we already have a list so should be easy
   * to just post requests in batches */
  rdma_wr.wr.next    = NULL;
  rdma_wr.wr.wr_cqe  = &qe->cqe;
  rdma_wr.wr.sg_list = sge;
  rdma_wr.wr.num_sge = 1;
  rdma_wr.wr.opcode  = op;
  rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
  rdma_wr.remote_addr = raddr;

  rdma_wr.rkey = get_rkey(raddr_block);
  if(rdma_wr.rkey == 0) {
    pr_err("remote address(%p) is invalid.\n", (void*)raddr);
    return -1;
  }

  atomic_inc(&q->pending);
  ret = ib_post_send(q->qp, &rdma_wr.wr, &bad_wr);
  if (unlikely(ret)) {
    pr_err("ib_post_send failed: %d\n", ret);
  }

  return ret;
}

/*
static void sswap_rdma_recv_remotemr_done(struct ib_cq *cq, struct ib_wc *wc)
{
  struct rdma_req *qe =
    container_of(wc->wr_cqe, struct rdma_req, cqe);
  struct rdma_queue *q = cq->cq_context;
  struct sswap_rdma_ctrl *ctrl = q->ctrl;
  struct ib_device *ibdev = q->ctrl->rdev->dev;

  if (unlikely(wc->status != IB_WC_SUCCESS)) {
    pr_err("sswap_rdma_recv_done status is not success\n");
    return;
  }
  ib_dma_unmap_single(ibdev, qe->dma, sizeof(struct sswap_rdma_memregion),
		      DMA_FROM_DEVICE);
  pr_info("servermr baseaddr=%llx, key=%u\n", ctrl->servermr.baseaddr,
	  ctrl->servermr.key);
  complete_all(&qe->done);
}
*/

/*
static int sswap_rdma_post_recv(struct rdma_queue *q, struct rdma_req *qe,
  size_t bufsize)
{
  const struct ib_recv_wr *bad_wr;
  struct ib_recv_wr wr = {};
  struct ib_sge sge;
  int ret;

  sge.addr = qe->dma;
  sge.length = bufsize;
  sge.lkey = q->ctrl->rdev->pd->local_dma_lkey;

  wr.next    = NULL;
  wr.wr_cqe  = &qe->cqe;
  wr.sg_list = &sge;
  wr.num_sge = 1;

  ret = ib_post_recv(q->qp, &wr, &bad_wr);
  if (ret) {
    pr_err("ib_post_recv failed: %d\n", ret);
  }
  return ret;
}
*/

/* allocates a sswap rdma request, creates a dma mapping for it in
 * req->dma, and synchronizes the dma mapping in the direction of
 * the dma map.
 * Don't touch the page with cpu after creating the request for it!
 * Deallocates the request if there was an error */
inline static int get_req_for_page(struct rdma_req **req, struct ib_device *dev,
				struct page *page, enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  (*req)->page = page;
  init_completion(&(*req)->done);

  (*req)->dma = ib_dma_map_page(dev, page, 0, PAGE_SIZE, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, PAGE_SIZE, dir);
out:
  return ret;
}

/* the buffer needs to come from kernel (not high memory) */
inline static int get_req_for_buf(struct rdma_req **req, struct ib_device *dev,
				void *buf, size_t size,
				enum dma_data_direction dir)
{
  int ret;

  ret = 0;
  *req = kmem_cache_alloc(req_cache, GFP_ATOMIC);
  if (unlikely(!req)) {
    pr_err("no memory for req\n");
    ret = -ENOMEM;
    goto out;
  }

  init_completion(&(*req)->done);

  (*req)->dma = ib_dma_map_single(dev, buf, size, dir);
  if (unlikely(ib_dma_mapping_error(dev, (*req)->dma))) {
    pr_err("ib_dma_mapping_error\n");
    ret = -ENOMEM;
    kmem_cache_free(req_cache, req);
    goto out;
  }

  ib_dma_sync_single_for_device(dev, (*req)->dma, size, dir);
out:
  return ret;
}

inline static void sswap_rdma_wait_completion(struct ib_cq *cq,
					      struct rdma_req *qe)
{
  ndelay(1000);
  while (!completion_done(&qe->done)) {
    ndelay(250);
    ib_process_cq_direct(cq, 1);
  }
}

/* polls queue until we reach target completed wrs or qp is empty */
static inline int poll_target(struct rdma_queue *q, int target)
{
  unsigned long flags;
  int completed = 0;

  while (completed < target && atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    completed += ib_process_cq_direct(q->cq, target - completed);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return completed;
}

static inline int drain_queue(struct rdma_queue *q)
{
  unsigned long flags;

  while (atomic_read(&q->pending) > 0) {
    spin_lock_irqsave(&q->cq_lock, flags);
    ib_process_cq_direct(q->cq, 16);
    spin_unlock_irqrestore(&q->cq_lock, flags);
    cpu_relax();
  }

  return 1;
}

static inline int write_queue_add(struct rdma_queue *q, struct page *page,
				  u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR - 8) {
    BUG_ON(inflight > QP_MAX_SEND_WR);
    poll_target(q, 2048);
    pr_info_ratelimited("back pressure writes");
  }

  ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;

  req->cqe.done = sswap_rdma_write_done;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, /*rkey,*/IB_WR_RDMA_WRITE);

  return ret;
}

static inline int begin_read(struct rdma_queue *q, struct page *page,
			     u64 roffset)
{
  struct rdma_req *req;
  struct ib_device *dev = q->ctrl->rdev->dev;
  struct ib_sge sge = {};
  int ret, inflight;

  /* back pressure in-flight reads, can't send more than
   * QP_MAX_SEND_WR at a time */
  while ((inflight = atomic_read(&q->pending)) >= QP_MAX_SEND_WR) {
    BUG_ON(inflight > QP_MAX_SEND_WR); /* only valid case is == */
    poll_target(q, 8);
    pr_info_ratelimited("back pressure happened on reads");
  }

  ret = get_req_for_page(&req, dev, page, DMA_TO_DEVICE);
  if (unlikely(ret))
    return ret;

  req->cqe.done = sswap_rdma_read_done;
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset,IB_WR_RDMA_READ);
  return ret;
}

int sswap_rdma_write(struct page *page, u64 roffset)
{
  int ret;
  struct rdma_queue *q;
  u64 page_offset = roffset;
  u64 raddr = offset_to_rpage_addr[page_offset];

  BUG_ON(roffset >= num_pages_total);
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);

  if(raddr == 0) {
    raddr = alloc_remote_page();
    if(raddr == 0) {
      pr_err("bad remote page alloc\n");
      return -1;
    }
    offset_to_rpage_addr[page_offset] = raddr;

    atomic64_inc(&num_swap_pages);
  }

  BUG_ON(raddr == 0);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);

  ret = write_queue_add(q, page, raddr);
  BUG_ON(ret);
  drain_queue(q);

  return ret;
}
EXPORT_SYMBOL(sswap_rdma_write);

static int sswap_rdma_recv_remotemr_fake(struct sswap_rdma_ctrl *ctrl)
{
  return 0;
}

/* page is unlocked when the wr is done.
 * posts an RDMA read on this cpu's qp */
int sswap_rdma_read_async(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;
  u64 raddr = offset_to_rpage_addr[roffset];

  BUG_ON(roffset >= num_pages_total);
  BUG_ON(raddr == 0);
  BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  
  ret = begin_read(q, page, raddr/*, rkey*/);


  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

void sswap_rdma_free_page(u64 roffset) {
  int page_offset = roffset;

  BUG_ON(roffset >= num_pages_total);

  if(offset_to_rpage_addr[page_offset] == 0) {
    return;
  }
  free_remote_page(offset_to_rpage_addr[page_offset]);
  offset_to_rpage_addr[page_offset] = 0;
  atomic64_dec(&num_swap_pages);

  return;
}
EXPORT_SYMBOL(sswap_rdma_free_page);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;
  u64 raddr = offset_to_rpage_addr[roffset];

  BUG_ON(raddr == 0);
  BUG_ON(roffset >= num_pages_total);
  BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read(q, page, raddr);

  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_poll_load(int cpu)
{
  struct rdma_queue *q = sswap_rdma_get_queue(cpu, QP_READ_SYNC);
  return drain_queue(q);
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

/* idx is absolute id (i.e. > than number of cpus) */
inline enum qp_type get_queue_type(unsigned int idx)
{
  // numcpus = 8
  if (idx < numcpus)
    return QP_READ_SYNC;
  else if (idx < numcpus * 2)
    return QP_READ_ASYNC;
  else if (idx < numcpus * 3)
    return QP_WRITE_SYNC;

  BUG();
  return QP_READ_SYNC;
}

inline struct rdma_queue *sswap_rdma_get_queue(unsigned int cpuid,
					       enum qp_type type)
{
  BUG_ON(gctrl == NULL);

  switch (type) {
    case QP_READ_SYNC:
      return &gctrl->queues[cpuid];
    case QP_READ_ASYNC:
      return &gctrl->queues[cpuid + numcpus];
    case QP_WRITE_SYNC:
      return &gctrl->queues[cpuid + numcpus * 2];
    default:
      BUG();
  };
}

void swap_pages_timer_callback(struct timer_list *timer) {
  int num_alloc_blocks_tmp = atomic64_read(&num_alloc_blocks);
  int num_free_blocks_tmp = atomic64_read(&num_free_blocks);
  int num_free_fail_tmp = atomic64_read(&num_free_fail);

  pr_info("num_alloc_blocks = %d, num_free_blocks = %d, num_free_fail = %d\n", num_alloc_blocks_tmp, num_free_blocks_tmp, num_free_fail_tmp);
  mod_timer(timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL)); 
}

static int __init sswap_rdma_init_module(void)
{
  int ret;
  int i = 0;
  uint64_t raddr = 0;
  uint32_t rkey = 0;

  pr_info("start: %s\n", __FUNCTION__);
  pr_info("* RDMA BACKEND *");

  numcpus = num_online_cpus();
  numqueues = numcpus * 3 + 1;
  rpc_queue_id = numqueues - 1;

  req_cache = kmem_cache_create("sswap_req_cache", sizeof(struct rdma_req), 0,
                      SLAB_TEMPORARY | SLAB_HWCACHE_ALIGN, NULL);

  if (!req_cache) {
    pr_err("no memory for cache allocation\n");
    return -ENOMEM;
  }

  ib_register_client(&sswap_rdma_ib_client);
  ret = sswap_rdma_create_ctrl(&gctrl);
  if (ret) {
    pr_err("could not create ctrl\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  ret = sswap_rdma_recv_remotemr_fake(gctrl);
  if (ret) {
    pr_err("could not setup remote memory region\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  
  for(i = 0;i < num_pages_total; ++i) {
    offset_to_rpage_addr[i] = 0; 
  }

  //ret = sswap_rdma_write_read_test();
  //if(ret) {
    //pr_err("sswap rdma write&read test failed.\n");
    //ib_unregister_client(&sswap_rdma_ib_client);
    //return -ENODEV;
  //}

  timer_setup(&swap_pages_timer, swap_pages_timer_callback, 0);
  mod_timer(&swap_pages_timer, jiffies + msecs_to_jiffies(INFO_PRINT_TINTERVAL));

  pr_info("ctrl is ready for reqs\n");

  /* rpc test */

  rdma_alloc_remote_block(&raddr, &rkey);
  pr_info("rblock address: %lld, rkey: %d", raddr, rkey);

  return 0;
}

module_init(sswap_rdma_init_module);
module_exit(sswap_rdma_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Experiments");
