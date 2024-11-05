#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALLOC 1
#define FREE 2
#define BATCH_SIZE 128
#define NUM_THREADS 4

struct rdma_server {
    struct rdma_cm_id *listen_id;
    struct rdma_cm_id *client_id;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr;
    unsigned long *buffer;
    size_t buffer_size;
};

struct rdma_server server;
pthread_t threads[NUM_THREADS];

void handle_message(int msg_type, int thread_id) {
    if (msg_type == ALLOC) {
        printf("Thread %d: Handling ALLOC request\n", thread_id);

        // 填充数据返回给客户端
        for (int i = 0; i < BATCH_SIZE; i++) {
            server.buffer[i] = i;
        }

        // 向客户端发送数据
        struct ibv_sge sge;
        struct ibv_send_wr wr, *bad_wr;
        sge.addr = (uintptr_t)server.buffer;
        sge.length = server.buffer_size;
        sge.lkey = server.mr->lkey;

        memset(&wr, 0, sizeof(wr));
        wr.wr_id = 0;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_SEND;
        wr.send_flags = IBV_SEND_SIGNALED;

        if (ibv_post_send(server.qp, &wr, &bad_wr)) {
            perror("Failed to send data to client");
        }
    } else if (msg_type == FREE) {
        printf("Thread %d: Handling FREE request with data:\n", thread_id);
        for (int i = 0; i < BATCH_SIZE; i++) {
            printf("%lu ", server.buffer[i]);
        }
        printf("\n");
    }
}

void *worker_thread(void *arg) {
    int thread_id = *((int *)arg);
    struct ibv_wc wc;

    while (1) {
        if (ibv_poll_cq(server.cq, 1, &wc) > 0) {
            if (wc.status == IBV_WC_SUCCESS) {
                int *msg_type = (int *)server.buffer;
                handle_message(*msg_type, thread_id);
            } else {
                fprintf(stderr, "Thread %d: CQ error %d\n", thread_id, wc.status);
            }
        }
    }
    return NULL;
}

void setup_rdma_server() {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(20079);

    if (rdma_create_id(NULL, &server.listen_id, NULL, RDMA_PS_TCP)) {
        perror("rdma_create_id failed");
        exit(1);
    }

    if (rdma_bind_addr(server.listen_id, (struct sockaddr *)&addr)) {
        perror("rdma_bind_addr failed");
        exit(1);
    }

    if (rdma_listen(server.listen_id, 1)) {
        perror("rdma_listen failed");
        exit(1);
    }
    
    printf("Server is listening on port %d\n", ntohs(addr.sin_port));

    if (rdma_get_request(server.listen_id, &server.client_id)) {
        perror("rdma_get_request failed");
        exit(1);
    }

    server.pd = ibv_alloc_pd(server.client_id->verbs);
    server.cq = ibv_create_cq(server.client_id->verbs, 10, NULL, NULL, 0);

    struct ibv_qp_init_attr qp_attr = {
        .send_cq = server.cq,
        .recv_cq = server.cq,
        .qp_type = IBV_QPT_RC,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
    };

    if (rdma_create_qp(server.client_id, server.pd, &qp_attr)) {
        perror("rdma_create_qp failed");
        exit(1);
    }
    server.qp = server.client_id->qp;

    struct rdma_conn_param conn_param = {0};
    if (rdma_accept(server.client_id, &conn_param)) {
        perror("rdma_accept failed");
        exit(1);
    }

    server.buffer_size = BATCH_SIZE * sizeof(unsigned long);
    server.buffer = malloc(server.buffer_size);
    server.mr = ibv_reg_mr(server.pd, server.buffer, server.buffer_size,
                           IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    if (!server.mr) {
        perror("ibv_reg_mr failed");
        exit(1);
    }
}

int main() {
    setup_rdma_server();

    int thread_ids[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            exit(1);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    ibv_dereg_mr(server.mr);
    free(server.buffer);
    rdma_destroy_qp(server.client_id);
    rdma_destroy_id(server.client_id);
    rdma_destroy_id(server.listen_id);
    return 0;
}
