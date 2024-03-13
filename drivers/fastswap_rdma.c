#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "fastswap_rdma.h"
#include <linux/slab.h>
#include <linux/cpumask.h> 
#include <linux/delay.h>
#include <linux/directswap.h>

static struct sswap_rdma_ctrl *gctrl;
static int serverport;
static int numqueues;
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
#define DAEMON_CORE 31

static struct task_struct *thread;

static int kfifos_daemon(void* data) {
  int i, count, ret, idx, offset;
  swp_entry_t entry;
  idx = 0;
  while(!kthread_should_stop()) {
    /*
    * [DirectSwap] Step1: Recycle freed pages
    */
    for(i = 0;i < NUM_KFIFOS_FREE; ++i) {
      count = 0;
      while (!kfifo_is_empty(kfifos_free + i) /*&& !kfifo_is_full(&central_heap)*/ && count < PAGES_PER_KFIFO_FREE) {
        ret = kfifo_out(kfifos_free + i, &entry, sizeof(entry));
        if (ret != sizeof(entry)) {
          printk(KERN_ERR "Failed to read from FIFO (in step %d)\n", 1);
          break;
        }
        
        offset = swp_offset(entry);
        BUG_ON(offset >= num_pages_total);
        BUG_ON(central_heap[offset] != 'U');
        central_heap[offset] = 'F';
        /*
        while(!kfifo_in(&central_heap, &entry, sizeof(entry))) {
          count++;
        }*/
        
        count++;
      }
    }

    /*
    * [DirectSwap] Step2: Fill unused pages
    */
    for(i = 0;i < NUM_KFIFOS_ALLOC; ++i) {
      count = 0;
      while (!kfifo_is_full(kfifos_alloc + i) /*&& !kfifo_is_empty(&central_heap)*/ && count < PAGES_PER_KFIFO_ALLOC) {
        /*
        ret = kfifo_out(&central_heap, &entry, sizeof(entry));
        if (ret != sizeof(entry)) {
            printk(KERN_ERR "Failed to read from FIFO (in step %d)\n", 2);
            break;
        }*/
        while(central_heap[idx] != 'F') {
          idx = (idx + 1) % num_pages_total;
        }
        entry = swp_entry(MAX_SWAPFILES-1, idx);
        while(!kfifo_in(kfifos_alloc + i, &entry, sizeof(entry))) {
          count++;
        }
        central_heap[idx] = 'U';
        count++;
      }
    }
  }
  return 0;
}

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
  }

  return q->ctrl->rdev;

out_free_pd:
  ib_dealloc_pd(rdev->pd);
out_free_dev:
  kfree(rdev);
out_err:
  return NULL;
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
  param.private_data = 0;
  param.private_data_len = 1;

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
  kfree(base_address);
  kfree(remote_keys);
  if (thread) {
    kthread_stop(thread);
  }
  //kfifo_free(&central_heap);

  return;
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
  struct ib_sge *sge, u64 raddr, u32 rkey, enum ib_wr_opcode op)
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
  rdma_wr.remote_addr = /*q->ctrl->servermr.baseaddr +*/ raddr;

  //bi = rhashtable_lookup_fast(blocks_map, &raddr_, blocks_map_params);
  //if(!bi || bi->rkey == 0) {
    //pr_err("cannot get rkey\n");
    //return -1;
  //}
  //rdma_wr.rkey = get_rkey(raddr_block);
  rdma_wr.rkey = rkey;
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
				  u64 roffset, u32 rkey)
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
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, rkey, IB_WR_RDMA_WRITE);

  return ret;
}

static inline int begin_read(struct rdma_queue *q, struct page *page,
			     u64 roffset, u32 rkey)
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
  ret = sswap_rdma_post_rdma(q, req, &sge, roffset, rkey,IB_WR_RDMA_READ);
  return ret;
}

int sswap_rdma_write(struct page *page, u64 roffset)
{
  int ret;
  struct rdma_queue *q;
  //int num_swap_pages_tmp;
  u64 page_offset = roffset;
  u64 raddr = offset_to_rpage_addr[page_offset];
  //u64 raddr_block = 0;
  u32 rkey = get_rkey((roffset >> BLOCK_SHIFT) << BLOCK_SHIFT);

  BUG_ON(roffset >= num_pages_total);
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);

  if(raddr == 0) {
    //spin_lock(locks+ (page_offset % num_groups));
    raddr = alloc_remote_page();
    if(raddr == 0) {
      pr_err("bad remote page alloc\n");
      //spin_unlock(locks + (page_offset % num_groups));
      return -1;
    }
    offset_to_rpage_addr[page_offset] = raddr;
    // spin_unlock(locks + (page_offset % num_groups));

    atomic_inc(&num_swap_pages);
    /*
    num_swap_pages_tmp = atomic_read(&num_swap_pages);
    if(num_swap_pages_tmp % print_interval == 0) {
      pr_info("num_swap_pages = %d, swap memory = %d GB\n", num_swap_pages_tmp, (num_swap_pages_tmp >> 18));
    }*/

  }

  BUG_ON(raddr == 0);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);

  //raddr_block = raddr >> BLOCK_SHIFT;
  //raddr_block = raddr_block << BLOCK_SHIFT;
  //rkey = get_rkey(raddr_block);
  //if(rkey == 0) {
    //pr_err("read_async:remote address(%p) is invalid.\n", (void*)raddr);
    //return -1;
  //}
  ret = write_queue_add(q, page, raddr, rkey);
  BUG_ON(ret);
  drain_queue(q);

  return ret;
}
EXPORT_SYMBOL(sswap_rdma_write);

/*
static int sswap_rdma_recv_remotemr_fake(struct sswap_rdma_ctrl *ctrl)
{
  ctrl->servermr.baseaddr = 0;
  ctrl->servermr.key = 0;
  return 0;
}
*/


static int sswap_rdma_recv_remotemr(struct sswap_rdma_ctrl *ctrl)
{
  struct rdma_req *qe;
  int ret;
  struct ib_device *dev;

  pr_info("start: %s\n", __FUNCTION__);
  dev = ctrl->rdev->dev;

  ret = get_req_for_buf(&qe, dev, &(ctrl->servermr), sizeof(ctrl->servermr),
			DMA_FROM_DEVICE);
  if (unlikely(ret))
    goto out;

  qe->cqe.done = sswap_rdma_recv_remotemr_done;

  ret = sswap_rdma_post_recv(&(ctrl->queues[0]), qe, sizeof(struct sswap_rdma_memregion));

  if (unlikely(ret))
    goto out_free_qe;

  sswap_rdma_wait_completion(ctrl->queues[0].cq, qe);

out_free_qe:
  kmem_cache_free(req_cache, qe);
out:
  return ret;
}

/* page is unlocked when the wr is done.
 * posts an RDMA read on this cpu's qp */
int sswap_rdma_read_async(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;
  u64 raddr = offset_to_rpage_addr[roffset];
  u64 raddr_block;
  u32 rkey = 0;

  BUG_ON(roffset >= num_pages_total);
  BUG_ON(raddr == 0);
  BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  
  raddr_block = raddr >> BLOCK_SHIFT;
  raddr_block = raddr_block << BLOCK_SHIFT;
  rkey = get_rkey(raddr_block);
  if(rkey == 0) {
    pr_err("read_async:remote address(%p) is invalid.\n", (void*)raddr);
    return -1;
  }
  ret = begin_read(q, page, raddr, rkey);


  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_async);

void sswap_rdma_free_page(u64 roffset) {
  //int num_swap_pages_tmp;
  int page_offset = roffset/*>> PAGE_SHIFT*/;

  BUG_ON(roffset >= num_pages_total);

  //spin_lock(locks + (page_offset % num_groups));
  if(offset_to_rpage_addr[page_offset] == 0) {
    //pr_err("no mapping for the page being free\n");
    //spin_unlock(locks + (page_offset % num_groups));
    return;
  }
  free_remote_page(offset_to_rpage_addr[page_offset]);
  offset_to_rpage_addr[page_offset] = 0;
  //spin_unlock(locks + (page_offset % num_groups));
  atomic_dec(&num_swap_pages);

  /*
  num_swap_pages_tmp = atomic_read(&num_swap_pages);
  if(num_swap_pages_tmp % print_interval == 0) {
      pr_info("num_swap_pages = %d\n", num_swap_pages_tmp);
  }*/

  return;
}
EXPORT_SYMBOL(sswap_rdma_free_page);

int sswap_rdma_read_sync(struct page *page, u64 roffset)
{
  struct rdma_queue *q;
  int ret;
  u64 raddr = offset_to_rpage_addr[roffset];
  u64 raddr_block;
  u32 rkey = 0;

  BUG_ON(raddr == 0);
  BUG_ON(roffset >= num_pages_total);
  BUG_ON((raddr & ((1 << PAGE_SHIFT) - 1)) != 0);
  VM_BUG_ON_PAGE(!PageSwapCache(page), page);
  VM_BUG_ON_PAGE(!PageLocked(page), page);
  VM_BUG_ON_PAGE(PageUptodate(page), page);

  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  raddr_block = raddr >> BLOCK_SHIFT;
  raddr_block = raddr_block << BLOCK_SHIFT;
  rkey = get_rkey(raddr_block);
  if(rkey == 0) {
    pr_err("read_sync:remote address(%p) is invalid.\n", (void*)raddr);
    return -1;
  }
  ret = begin_read(q, page, raddr, rkey);

  return ret;
}
EXPORT_SYMBOL(sswap_rdma_read_sync);

int sswap_rdma_poll_load(int cpu)
{
  struct rdma_queue *q = sswap_rdma_get_queue(cpu, QP_READ_SYNC);
  return drain_queue(q);
}
EXPORT_SYMBOL(sswap_rdma_poll_load);

int direct_swap_rdma_read_async(struct page *page, u64 roffset, int type) {
  struct rdma_queue *q;
  int id = remote_area_id(type);
  u64 raddr = base_address[id] + (roffset << PAGE_SHIFT);
  u32 rkey = remote_keys[id];
  int ret;
  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_ASYNC);
  ret = begin_read(q, page, raddr, rkey);

  return ret;
}
EXPORT_SYMBOL(direct_swap_rdma_read_async);

int direct_swap_rdma_read_sync(struct page *page, u64 roffset, int type) {
  struct rdma_queue *q;
  int id = remote_area_id(type);
  u64 raddr = base_address[id] + (roffset << PAGE_SHIFT);
  u32 rkey = remote_keys[id];
  int ret;
  q = sswap_rdma_get_queue(smp_processor_id(), QP_READ_SYNC);
  ret = begin_read(q, page, raddr, rkey);

  return ret;
}
EXPORT_SYMBOL(direct_swap_rdma_read_sync);

int direct_swap_rdma_write(struct page *page, u64 roffset, int type) {
  struct rdma_queue *q;
  int id = remote_area_id(type);
  u64 raddr = base_address[id] + (roffset << PAGE_SHIFT);
  u32 rkey = remote_keys[id];
  int ret;
  q = sswap_rdma_get_queue(smp_processor_id(), QP_WRITE_SYNC);
  ret = write_queue_add(q, page, raddr, rkey);
  
  //BUG_ON(ret);
  drain_queue(q);
  if(!ret) {
    atomic_inc(&num_direct_swap_pages);
  }
  return ret;
}
EXPORT_SYMBOL(direct_swap_rdma_write);

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
  int num_swap_pages_tmp = atomic_read(&num_swap_pages);
  int num_alloc_blocks_tmp = atomic_read(&num_alloc_blocks);
  int num_free_blocks_tmp = atomic_read(&num_free_blocks);
  int num_free_fail_tmp = atomic_read(&num_free_fail);
  int num_direct_swap_pages_tmp = atomic_read(&num_direct_swap_pages);

  pr_info("used swap memory = %d MB, current alloc memory = %d MB\n", (num_swap_pages_tmp >> (MB_SHIFT - PAGE_SHIFT)), ((num_alloc_blocks_tmp - num_free_blocks_tmp) << (BLOCK_SHIFT - MB_SHIFT)));
  pr_info("num_alloc_blocks = %d, num_free_blocks = %d, num_free_fail = %d\n", num_alloc_blocks_tmp, num_free_blocks_tmp, num_free_fail_tmp);
  pr_info("num_direct_swap_pages = %d\n", num_direct_swap_pages_tmp);
  mod_timer(timer, jiffies + msecs_to_jiffies(swap_pages_print_interval)); 
}

/*
static int sswap_rdma_write_read_test(void)
{
  struct page *page_ptr = NULL;
  void *page_vaddr;
  int* int_ptr;
  int ret;

  page_ptr = alloc_pages(GFP_KERNEL, 0);
  if (!page_ptr) {
    // handle error
    pr_err("cannot alloc physical frame.\n");
    return -1;
  }

  page_vaddr = page_address(page_ptr);
  int_ptr = (int*) page_vaddr;
  *int_ptr = 325423;

  ret = sswap_rdma_write(page_ptr, num_pages_total - 1);
  if(ret) {
    pr_err("write page failed\n");
    return -1;
  }

  msleep(1000);

  *int_ptr = 11111;

  BUG_ON(*int_ptr != 11111);

  ret = sswap_rdma_read_sync(page_ptr, num_pages_total - 1);
  if(ret) {
    pr_err("read page failed\n");
    return -1;
  }
  
  msleep(1000);

  page_vaddr = page_address(page_ptr);
  int_ptr = (int*) page_vaddr;
  //BUG_ON(*int_ptr != 325423);

  if(*int_ptr == 325423) {
    pr_info("test pass\n");
  } else {
    pr_err("test failed with int = %d\n",(*int_ptr));
    return -1;
  }

  __free_pages(page_ptr, 0);

  sswap_rdma_free_page(num_pages_total - 1);

  return 0;
}*/

static int central_heap_init(void)
{
  int i;
  //swp_entry_t entry;

  base_address[0] = gctrl->servermr.baseaddr;
  remote_keys[0] = gctrl->servermr.key;
  /*
  ret = kfifo_alloc(&central_heap, sizeof(swp_entry)*num_pages_total, GFP_KERNEL);
	if(unlikely(ret)) {
		pr_err("Alloc memory for kfifos_alloc failed with error code %d.", ret);
    return ret;
	}*/

  for(i = 0;i < num_pages_total; ++i) {
    /*
    entry = swp_entry(MAX_SWAPFILES - 1, i);
    kfifo_in(&central_heap, &entry, sizeof(swp_entry_t));*/
    central_heap[i] = 'F';
  }
  return 0;
}

static int __init sswap_rdma_init_module(void)
{
  int ret;
  int i = 0;

  pr_info("start: %s\n", __FUNCTION__);
  pr_info("* RDMA BACKEND *");

  numcpus = num_online_cpus();
  numqueues = numcpus * 3;

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

  ret = sswap_rdma_recv_remotemr(gctrl);
  if (ret) {
    pr_err("could not setup remote memory region\n");
    ib_unregister_client(&sswap_rdma_ib_client);
    return -ENODEV;
  }

  for(i = 0;i < num_groups; ++i) {
    spin_lock_init(locks + i);
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
  mod_timer(&swap_pages_timer, jiffies + msecs_to_jiffies(swap_pages_print_interval));

  base_address = (u64 *)kmalloc(sizeof(u64) * NUM_REMOTE_SWAP_AREA, GFP_KERNEL);
  remote_keys = (u32 *)kmalloc(sizeof(u32) * NUM_REMOTE_SWAP_AREA, GFP_KERNEL);

  central_heap_init();

  thread = kthread_create(kfifos_daemon, NULL, "directswap_kfifos_daemon");
  if (IS_ERR(thread)) {
    printk(KERN_ERR "Failed to create kernel thread\n");
    return PTR_ERR(thread);
  }
  kthread_bind(thread, DAEMON_CORE);
  wake_up_process(thread);


  pr_info("ctrl is ready for reqs\n");
  return 0;
}

module_init(sswap_rdma_init_module);
module_exit(sswap_rdma_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Experiments");
