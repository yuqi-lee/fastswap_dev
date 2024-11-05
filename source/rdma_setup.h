#include "rdma_demo.h"

void setup_rdma_connection(rdma_resources_t *res, int is_client) {
    // 初始化RDMA资源
    res->context = NULL; // 在实际代码中需填充RDMA设备和其他资源的初始化细节
    res->pd = ibv_alloc_pd(res->context);
    res->cq = ibv_create_cq(res->context, 10, NULL, NULL, 0);

    res->buf = malloc(MSG_SIZE);
    res->mr = ibv_reg_mr(res->pd, res->buf, MSG_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    struct ibv_qp_init_attr qp_init_attr = {
        .send_cq = res->cq,
        .recv_cq = res->cq,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 1,
            .max_recv_sge = 1
        },
        .qp_type = IBV_QPT_RC
    };
    res->qp = ibv_create_qp(res->pd, &qp_init_attr);

    // 配置QP和完成状态等。此部分略去具体代码。
}

void rdma_send(rdma_resources_t *res, unsigned long *data) {
    // 填充发送的缓冲区
    memcpy(res->buf, data, MSG_SIZE);
    struct ibv_sge sge = {
        .addr = (uintptr_t)res->buf,
        .length = MSG_SIZE,
        .lkey = res->mr->lkey
    };
    struct ibv_send_wr wr = {
        .next = NULL,
        .sg_list = &sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND
    };
    struct ibv_send_wr *bad_wr;
    ibv_post_send(res->qp, &wr, &bad_wr);
}

void rdma_recv(rdma_resources_t *res, unsigned long *buffer) {
    struct ibv_sge sge = {
        .addr = (uintptr_t)res->buf,
        .length = MSG_SIZE,
        .lkey = res->mr->lkey
    };
    struct ibv_recv_wr wr = {
        .next = NULL,
        .sg_list = &sge,
        .num_sge = 1
    };
    struct ibv_recv_wr *bad_wr;
    ibv_post_recv(res->qp, &wr, &bad_wr);

    // 等待接收完成（等待接收完成事件）代码略
    memcpy(buffer, res->buf, MSG_SIZE);
}

void teardown_rdma_connection(rdma_resources_t *res) {
    ibv_destroy_qp(res->qp);
    ibv_dereg_mr(res->mr);
    ibv_destroy_cq(res->cq);
    ibv_dealloc_pd(res->pd);
    free(res->buf);
}
