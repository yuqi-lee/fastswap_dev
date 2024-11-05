#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALLOC 1
#define FREE 2
#define BATCH_SIZE 128

struct rdma_client {
    struct rdma_cm_id *cm_id;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    struct ibv_mr *mr;
    unsigned long *buffer;
    size_t buffer_size;
};

void setup_rdma_client(struct rdma_client *client, const char *server_ip) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(20079);
    addr.sin_addr.s_addr = inet_addr(server_ip);

    if (rdma_create_id(NULL, &client->cm_id, NULL, RDMA_PS_TCP)) {
        perror("rdma_create_id failed");
        exit(1);
    }

    if (rdma_resolve_addr(client->cm_id, NULL, (struct sockaddr *)&addr, 2000)) {
        perror("rdma_resolve_addr failed");
        exit(1);
    }

    if (rdma_resolve_route(client->cm_id, 2000)) {
        perror("rdma_resolve_route failed");
        exit(1);
    }

    client->pd = ibv_alloc_pd(client->cm_id->verbs);
    client->cq = ibv_create_cq(client->cm_id->verbs, 10, NULL, NULL, 0);

    struct ibv_qp_init_attr qp_attr = {
        .send_cq = client->cq,
        .recv_cq = client->cq,
        .qp_type = IBV_QPT_RC,
        .cap = {
            .max_send_wr = 10,
            .max_recv_wr = 10,
            .max_send_sge = 1,
            .max_recv_sge = 1,
        },
    };

    if (rdma_create_qp(client->cm_id, client->pd, &qp_attr)) {
        perror("rdma_create_qp failed");
        exit(1);
    }
    client->qp = client->cm_id->qp;

    struct rdma_conn_param conn_param = {0};
    if (rdma_connect(client->cm_id, &conn_param)) {
        perror("rdma_connect failed");
        exit(1);
    }

    client->buffer_size = BATCH_SIZE * sizeof(unsigned long);
    client->buffer = malloc(client->buffer_size);
    client->mr = ibv_reg_mr(client->pd, client->buffer, client->buffer_size,
                            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    if (!client->mr) {
        perror("ibv_reg_mr failed");
        exit(1);
    }
}

void send_message(struct rdma_client *client, int msg_type) {
    struct ibv_sge sge;
    struct ibv_send_wr wr, *bad_wr;
    int *msg = (int *)client->buffer;
    *msg = msg_type;

    if (msg_type == FREE) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            client->buffer[i] = i;
        }
    }

    sge.addr = (uintptr_t)client->buffer;
    sge.length = client->buffer_size;
    sge.lkey = client->mr->lkey;

    memset(&wr, 0, sizeof(wr));
    wr.wr_id = 0;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND;
    wr.send_flags = IBV_SEND_SIGNALED;

    if (ibv_post_send(client->qp, &wr, &bad_wr)) {
        perror("Failed to send message");
    }

    if (msg_type == ALLOC) {
        struct ibv_wc wc;
        while (ibv_poll_cq(client->cq, 1, &wc) == 0);
        if (wc.status != IBV_WC_SUCCESS) {
            perror("RDMA receive error");
            exit(1);
        }
        printf("Received ALLOC data:\n");
        for (int i = 0; i < BATCH_SIZE; i++) {
            printf("%lu ", client->buffer[i]);
        }
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    struct rdma_client client;
    setup_rdma_client(&client, argv[1]);

    send_message(&client, ALLOC);
    send_message(&client, FREE);

    ibv_dereg_mr(client.mr);
    free(client.buffer);
    rdma_disconnect(client.cm_id);
    rdma_destroy_qp(client.cm_id);
    rdma_destroy_id(client.cm_id);

    return 0;
}
