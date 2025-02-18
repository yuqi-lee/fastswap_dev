#include "sys/sysinfo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cassert>
#include <rdma/rdma_cma.h>
#include <mutex>
#include <thread>
#include "../msg.h"

#define TEST_NZ(x) do { if ( (x)) die("error: " #x " failed (returned non-zero)." ); } while (0)
#define TEST_Z(x)  do { if (!(x)) die("error: " #x " failed (returned zero/null)."); } while (0)

const size_t BUFFER_SIZE = 1024 * 1024 * 1024 * 32l;
const unsigned int NUM_PROCS = 4;//get_nprocs_conf();
const unsigned int NUM_QUEUES_PER_PROC = 3;
const unsigned int NUM_QUEUES = NUM_PROCS * NUM_QUEUES_PER_PROC + 1;

struct device {
  struct ibv_pd *pd;
  struct ibv_context *verbs;
};

struct queue {
  struct ibv_qp *qp;
  struct ibv_cq *cq;
  struct rdma_cm_id *cm_id;
  struct ctrl *ctrl;
  enum {
    INIT,
    CONNECTED
  } state;
};

struct ctrl {
  struct queue *queues;
  struct ibv_mr *mr_buffer;
  //void *buffer;
  struct device *dev;

  struct ibv_comp_channel *comp_channel;

  std::thread *allocator;
  std::thread *recycler;

  struct message *recv_msg;
  struct message *send_msg;

  struct ibv_mr *recv_mr;
  struct ibv_mr *send_mr;
};


struct Block {
  uint64_t addr;
  uint32_t rkey;

  Block(uint64_t a, uint32_t k) : addr(a), rkey(k) {

  }

  Block() : addr(0), rkey(0) {

  }
};

struct BlockQueue {
  uint64_t begin;
  uint64_t end;
  Block* blocks;
  uint64_t block_num;
  uint64_t capacity;
  std::mutex mtx;

  BlockQueue(uint64_t len) : begin(0), end(0), block_num(0), capacity(len) {
    blocks = new Block[len];
    assert(blocks != nullptr);
  }

  ~BlockQueue() {
    delete[] blocks;
  }

  int allocate(uint64_t& addr, uint32_t& rkey) {
    if(block_num == 0)
      return -1;
    addr = blocks[begin].addr;
    rkey = blocks[begin].rkey;
    begin = (begin + 1) % capacity;
    block_num--;
    return 0;
  }

  int free(uint64_t addr, uint32_t rkey) {
    if(block_num == capacity)
      return -1;
    blocks[end].addr = addr;
    blocks[end].rkey = rkey;
    end = (end + 1) % capacity;
    block_num++;
    return 0;
  }
};
