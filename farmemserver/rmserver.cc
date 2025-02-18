
#include "rmserver.h"
#include <sys/mman.h>
#include <iostream>
#include <unistd.h> 

static void die(const char *reason);

static int alloc_control();
static int on_connect_request(struct rdma_cm_id *id, struct rdma_conn_param *param);
static int on_connection(struct queue *q);
static int on_disconnect(struct queue *q);
static int on_event(struct rdma_cm_event *event);
static void destroy_device(struct ctrl *ctrl);
void *poll_cq(void *ctx);
void* recycler(ibv_pd *pd);
void handle_cqe(struct ibv_wc *wc);

static struct ctrl *gctrl = NULL;
static unsigned int queue_ctr = 0;

#define MEM_ALIGN_SIZE 4096
#define CORE_ID 31
#define PAGE_SHIFT 12

const uint64_t TOTAL_PAGES =  16ULL * 1024 * 1024;
const uint64_t BLOCK_SIZE =  2ULL * 1024 * 1024;
const uint64_t REMOTE_MEM_SIZE =  32ULL * 1024 * 1024 * 1024;
const uint64_t NUM_BLOCKS = REMOTE_MEM_SIZE/BLOCK_SIZE;


struct BlockQueue *block_queue = nullptr;
struct BlockQueue *recycle_block_queue = nullptr;
struct ibv_mr** online_mrs = nullptr;
void* base_addr;

void init_block_queue(struct ibv_pd *pd) {
  base_addr = mmap((void*)0x1000000000, (REMOTE_MEM_SIZE), PROT_READ | PROT_WRITE, 
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if(base_addr == MAP_FAILED) {
    perror("mmap failed.");
  } 

  block_queue = new BlockQueue(NUM_BLOCKS);
  recycle_block_queue = new BlockQueue(NUM_BLOCKS);
  online_mrs = new ibv_mr*[NUM_BLOCKS];

  for(uint32_t i = 0; i < NUM_BLOCKS; ++i) {
    void* p = base_addr + (i * BLOCK_SIZE);
    assert(p);
    auto mr = ibv_reg_mr(pd, p, BLOCK_SIZE,
                 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if(mr == nullptr) {
      std::cout << "reg mr fail, with offset = " << i << std::endl;
      continue;
    }
    online_mrs[i] = mr;
    block_queue->free((uint64_t)p, mr->rkey);
  }

  std::cout << "successfully register " << REMOTE_MEM_SIZE << " bytes MR at " << base_addr << std::endl;
  std::cout << "blocks queue length is " << block_queue->block_num << std::endl;
}

int main(int argc, char **argv)
{
  struct sockaddr_in addr = {};
  struct rdma_cm_event *event = NULL;
  struct rdma_event_channel *ec = NULL;
  struct rdma_cm_id *listener = NULL;
  uint16_t port = 0;

  if (argc != 2) {
    die("Need to specify a port number to listen");
  }

  addr.sin_family = AF_INET;
  addr.sin_port = htons(atoi(argv[1]));

  TEST_NZ(alloc_control());

  TEST_Z(ec = rdma_create_event_channel());
  TEST_NZ(rdma_create_id(ec, &listener, NULL, RDMA_PS_TCP));
  TEST_NZ(rdma_bind_addr(listener, (struct sockaddr *)&addr));
  TEST_NZ(rdma_listen(listener, NUM_QUEUES + 1));
  port = ntohs(rdma_get_src_port(listener));
  printf("listening on port %d.\n", port);

  for (unsigned int i = 0; i < NUM_QUEUES; ++i) {
    printf("waiting for queue connection: %d\n", i);
    struct queue *q = &gctrl->queues[i];

    // handle connection requests
    while (rdma_get_cm_event(ec, &event) == 0) {
      struct rdma_cm_event event_copy;

      memcpy(&event_copy, event, sizeof(*event));
      rdma_ack_cm_event(event);

      if (on_event(&event_copy) || q->state == queue::CONNECTED)
        break;
    }
  }

  printf("done connecting all queues\n");

  // handle disconnects, etc.
  while (rdma_get_cm_event(ec, &event) == 0) {
    struct rdma_cm_event event_copy;

    memcpy(&event_copy, event, sizeof(*event));
    rdma_ack_cm_event(event);

    if (on_event(&event_copy))
      break;
  }

  rdma_destroy_event_channel(ec);
  rdma_destroy_id(listener);
  destroy_device(gctrl);
  return 0;
}

void die(const char *reason)
{
  fprintf(stderr, "%s - errno: %d\n", reason, errno);
  exit(EXIT_FAILURE);
}

int alloc_control()
{
  gctrl = (struct ctrl *) malloc(sizeof(struct ctrl));
  TEST_Z(gctrl);
  memset(gctrl, 0, sizeof(struct ctrl));

  gctrl->queues = (struct queue *) malloc(sizeof(struct queue) * NUM_QUEUES);
  TEST_Z(gctrl->queues);
  memset(gctrl->queues, 0, sizeof(struct queue) * NUM_QUEUES);
  for (unsigned int i = 0; i < NUM_QUEUES; ++i) {
    gctrl->queues[i].ctrl = gctrl;
    gctrl->queues[i].state = queue::INIT;
  }


  return 0;
}

void set_thread_affinity(std::thread* t, int core_id) {
    pthread_t native_handle = t->native_handle();

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);           
    CPU_SET(core_id, &cpuset);   

    int result = pthread_setaffinity_np(native_handle, sizeof(cpu_set_t), &cpuset);
    if (result != 0) {
        std::cerr << "Error setting thread affinity: " << result << std::endl;
    } else {
        std::cout << "Success setting thread affinity." << std::endl;
    }
    
}

static device *get_device(struct queue *q)
{
  struct device *dev = NULL;

  if (!q->ctrl->dev) {
    dev = (struct device *) malloc(sizeof(*dev));
    TEST_Z(dev);
    dev->verbs = q->cm_id->verbs;
    TEST_Z(dev->verbs);
    dev->pd = ibv_alloc_pd(dev->verbs);
    TEST_Z(dev->pd);

    struct ctrl *ctrl = q->ctrl;
    TEST_Z(ctrl == gctrl);

    TEST_Z(q->ctrl->comp_channel = ibv_create_comp_channel(q->cm_id->verbs));
    TEST_Z(q->cq = ibv_create_cq(q->cm_id->verbs, 10, NULL, ctrl->comp_channel, 0));
    TEST_NZ(ibv_req_notify_cq(q->cq, 0));

    init_block_queue(dev->pd);

    ctrl->allocator = new std::thread(poll_cq, nullptr);
    set_thread_affinity(ctrl->allocator, CORE_ID);
    ctrl->recycler = new std::thread(recycler, dev->pd);
    set_thread_affinity(ctrl->recycler, CORE_ID - 1);
    ctrl->dev = dev;
  }

  return q->ctrl->dev;
}

void *poll_cq(void *ctx) {
  struct ibv_cq *cq;
  struct ibv_wc wc;

  while (1) {
    TEST_NZ(ibv_get_cq_event(gctrl->comp_channel, &cq, &ctx));
    ibv_ack_cq_events(cq, 1);
    TEST_NZ(ibv_req_notify_cq(cq, 0));

    while (ibv_poll_cq(cq, 1, &wc))
      handle_cqe(&wc);
  }

  return NULL;
}

void post_receives(struct queue *q) {
  struct ibv_recv_wr wr, *bad_wr = NULL;
  struct ibv_sge sge;
  struct ctrl *rdma_session = q->ctrl;

  wr.wr_id = (uintptr_t)q;
  wr.next = NULL;
  wr.sg_list = &sge;
  wr.num_sge = 1;

  sge.addr = (uintptr_t)rdma_session->recv_msg;
  sge.length = (uint32_t)sizeof(struct message);
  sge.lkey = rdma_session->recv_mr->lkey;

  TEST_NZ(ibv_post_recv(q->qp, &wr, &bad_wr));
}

void send_message(struct queue *q) {
  struct ibv_send_wr wr, *bad_wr = NULL;
  struct ibv_sge sge;
  struct ctrl *rdma_session = q->ctrl;

  memset(&wr, 0, sizeof(wr));

  wr.wr_id = (uintptr_t)q;
  wr.opcode = IBV_WR_SEND;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.send_flags = IBV_SEND_SIGNALED;

  sge.addr = (uintptr_t)rdma_session->send_msg;
  sge.length = (uint32_t)sizeof(struct message);
  fprintf(stderr, "%s, message size = %lu\n", __func__, sizeof(struct message));
  sge.lkey = rdma_session->send_mr->lkey;

  TEST_NZ(ibv_post_send(q->qp, &wr, &bad_wr));
}

void alloc_new_block(struct queue *q) {
  int i, ret;
  uint64_t raddr = 0;
  uint32_t rkey = 0;
  struct ctrl *rdma_session = q->ctrl;

  block_queue->mtx.lock();
  ret = block_queue->allocate(raddr, rkey);
  block_queue->mtx.unlock();

  assert(raddr != 0);
  assert(rkey != 0);

  std::cout<< "remote block address: " << raddr << ", rkey: " << rkey << std::endl;

  rdma_session->send_msg->type = ALLOCATE_BLOCK;
  rdma_session->send_msg->addr = raddr;
  rdma_session->send_msg->rkey = rkey;
  rdma_session->send_msg->status = WORK;

  send_message(q);
}

void free_to_recycle_queue(struct queue *q) {
  int ret;
  uint64_t raddr = 0;
  uint32_t rkey = 0;
  struct ctrl *ctrl = q->ctrl;

  raddr = ctrl->recv_msg->addr;
  rkey = ctrl->recv_msg->rkey;
  assert(raddr != 0);
  assert(rkey != 0);

  recycle_block_queue->mtx.lock();
  ret = recycle_block_queue->free(raddr, rkey);
  recycle_block_queue->mtx.unlock();

  return;
}

void* recycler(ibv_pd *pd) {
  uint64_t addr;
  uint32_t rkey;

  while(true) {
    recycle_block_queue->mtx.lock();
    int ret = recycle_block_queue->allocate(addr, rkey);
    recycle_block_queue->mtx.unlock();
    while(ret != -1) {
      uint64_t offset = (addr - (uint64_t)base_addr) / BLOCK_SIZE;
      if(rkey == online_mrs[offset]->rkey) {
        ibv_dereg_mr(online_mrs[offset]);
        struct ibv_mr* new_mr = ibv_reg_mr(pd, (void*)addr, BLOCK_SIZE,
                 IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
        online_mrs[offset] = new_mr;
        block_queue->mtx.lock();
        block_queue->free(addr, new_mr->rkey);
        block_queue->mtx.lock();
      } else {
        // just skip ...
      }
      recycle_block_queue->mtx.lock();
      int ret = recycle_block_queue->allocate(addr, rkey);
      recycle_block_queue->mtx.unlock();
    }
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
}

void handle_cqe(struct ibv_wc *wc) {

  struct queue *q =
      (struct queue *)(uintptr_t)wc->wr_id;
  struct ctrl *ctrl = q->ctrl;

  if (wc->status != IBV_WC_SUCCESS)
    die("handle_cqe: status is not IBV_WC_SUCCESS.");

  if (wc->opcode == IBV_WC_RECV) {
    switch (ctrl->recv_msg->type) {
    case ALLOCATE_BLOCK:
      std::cout<<"....." << std::endl << std::endl;
      std::cout<<"recieve a allocate request" << std::endl;
      std::cout<< std::endl << std::endl << "....." << std::endl;
      alloc_new_block(q);
      post_receives(q);
      break;

    case FREE_BLOCK:
      free_to_recycle_queue(q);
      break;

    }
  } else if (wc->opcode == IBV_WC_SEND) {
    fprintf(stderr, "%s, 2-sided RDMA message sent done ?\n", __func__);
  } else {
    fprintf(stderr, "%s, recived wc.opcode %d\n", __func__, wc->opcode);
  }
}


static void destroy_device(struct ctrl *ctrl)
{
  TEST_Z(ctrl->dev);

  ibv_dereg_mr(ctrl->mr_buffer);
  //free(ctrl->buffer);
  ibv_dealloc_pd(ctrl->dev->pd);
  free(ctrl->dev);
  ctrl->dev = NULL;
}

static void create_qp(struct queue *q)
{
  struct ibv_qp_init_attr qp_attr = {};

  qp_attr.send_cq = q->cq;
  qp_attr.recv_cq = q->cq;
  qp_attr.qp_type = IBV_QPT_RC;
  qp_attr.cap.max_send_wr = 10;
  qp_attr.cap.max_recv_wr = 10;
  qp_attr.cap.max_send_sge = 1;
  qp_attr.cap.max_recv_sge = 1;

  TEST_NZ(rdma_create_qp(q->cm_id, q->ctrl->dev->pd, &qp_attr));
  q->qp = q->cm_id->qp;
}

int on_connect_request(struct rdma_cm_id *id, struct rdma_conn_param *param)
{

  struct rdma_conn_param cm_params = {};
  struct ibv_device_attr attrs = {};
  struct queue *q = &gctrl->queues[queue_ctr++];

  TEST_Z(q->state == queue::INIT);
  printf("%s\n", __FUNCTION__);

  id->context = q;
  q->cm_id = id;

  struct device *dev = get_device(q);
  create_qp(q);

  TEST_NZ(ibv_query_device(dev->verbs, &attrs));

  //printf("attrs: max_qp=%d, max_qp_wr=%d, max_cq=%d max_cqe=%d \
          max_qp_rd_atom=%d, max_qp_init_rd_atom=%d\n", attrs.max_qp,
  //        attrs.max_qp_wr, attrs.max_cq, attrs.max_cqe,
  //        attrs.max_qp_rd_atom, attrs.max_qp_init_rd_atom);

  //printf("ctrl attrs: initiator_depth=%d responder_resources=%d\n",
  //    param->initiator_depth, param->responder_resources);

  // the following should hold for initiator_depth:
  // initiator_depth <= max_qp_init_rd_atom, and
  // initiator_depth <= param->initiator_depth
  cm_params.initiator_depth = param->initiator_depth;
  // the following should hold for responder_resources:
  // responder_resources <= max_qp_rd_atom, and
  // responder_resources >= param->responder_resources
  cm_params.responder_resources = param->responder_resources;
  cm_params.rnr_retry_count = param->rnr_retry_count;
  cm_params.flow_control = param->flow_control;

  TEST_NZ(rdma_accept(q->cm_id, &cm_params));

  return 0;
}

int on_connection(struct queue *q)
{
  printf("%s\n", __FUNCTION__);
  struct ctrl *ctrl = q->ctrl;

  TEST_Z(q->state == queue::INIT);

  if (q == &ctrl->queues[0]) {
    // Yuqi: no need to notify global MR.
  }

  q->state = queue::CONNECTED;
  return 0;
}

int on_disconnect(struct queue *q)
{
  printf("%s\n", __FUNCTION__);

  if (q->state == queue::CONNECTED) {
    q->state = queue::INIT;
    rdma_destroy_qp(q->cm_id);
    rdma_destroy_id(q->cm_id);
  }

  return 0;
}

int on_event(struct rdma_cm_event *event)
{
  printf("%s\n", __FUNCTION__);
  struct queue *q = (struct queue *) event->id->context;

  switch (event->event) {
    case RDMA_CM_EVENT_CONNECT_REQUEST:
      return on_connect_request(event->id, &event->param.conn);
    case RDMA_CM_EVENT_ESTABLISHED:
      return on_connection(q);
    case RDMA_CM_EVENT_DISCONNECTED:
      on_disconnect(q);
      return 1;
    default:
      printf("unknown event: %s\n", rdma_event_str(event->event));
      return 1;
  }
}

