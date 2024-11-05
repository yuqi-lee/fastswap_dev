#include "rdma_demo.h"

int main() {
    rdma_resources_t server_res;
    unsigned long recv_data[BATCH_SIZE];

    // 初始化RDMA资源并建立连接
    setup_rdma_connection(&server_res, 0);  // 0表示服务端

    // 接收客户端的ALLOC请求数据
    rdma_recv(&server_res, recv_data);

    // 在此进行业务处理，如打印接收到的数据
    printf("Server received ALLOC data: ");
    for (int i = 0; i < BATCH_SIZE; i++) {
        printf("%lu ", recv_data[i]);
    }
    printf("\n");

    // 响应客户端的FREE请求（假设此处重用recv_data作为响应数据）
    rdma_send(&server_res, recv_data);

    // 清理RDMA连接
    teardown_rdma_connection(&server_res);

    return 0;
}
