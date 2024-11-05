#ifndef RDMA_DEMO_H
#define RDMA_DEMO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <infiniband/verbs.h>

#define BATCH_SIZE 128  // BATCH_SIZE定义为10，可以根据需求调整
#define MSG_SIZE (BATCH_SIZE * sizeof(unsigned long))  // 消息大小

typedef struct {
    struct ibv_context *context;
    struct ibv_pd *pd;
    struct ibv_mr *mr;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    void *buf;
} rdma_resources_t;

void setup_rdma_connection(rdma_resources_t *res, int is_client);
void rdma_send(rdma_resources_t *res, unsigned long *data);
void rdma_recv(rdma_resources_t *res, unsigned long *buffer);
void teardown_rdma_connection(rdma_resources_t *res);

#endif
