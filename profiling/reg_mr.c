#include <stdio.h>
#include <stdlib.h>
#include <infiniband/verbs.h>

#define NUM_REGIONS 100
#define REGION_SIZE (128 * 1024 * 1024) 

int main() {
    struct ibv_device **dev_list;
    struct ibv_device *ib_dev;
    struct ibv_context *context;
    struct ibv_pd *pd;
    struct ibv_mr *mr[NUM_REGIONS];
    void *regions[NUM_REGIONS];
    int i;

    // 获取设备列表
    dev_list = ibv_get_device_list(NULL);
    if (!dev_list) {
        perror("Failed to get IB devices list");
        return 1;
    }

    // 选择第一个设备
    ib_dev = dev_list[0];
    if (!ib_dev) {
        fprintf(stderr, "No IB devices found\n");
        return 1;
    }

    // 打开设备
    context = ibv_open_device(ib_dev);
    if (!context) {
        fprintf(stderr, "Failed to open device\n");
        return 1;
    }

    // 分配保护域
    pd = ibv_alloc_pd(context);
    if (!pd) {
        fprintf(stderr, "Failed to allocate PD\n");
        return 1;
    }

    // 分配内存并注册内存区域
    for (i = 0; i < NUM_REGIONS; i++) {
        regions[i] = malloc(REGION_SIZE);
        if (!regions[i]) {
            fprintf(stderr, "Failed to allocate memory for region %d\n", i);
            return 1;
        }

        mr[i] = ibv_reg_mr(pd, regions[i], REGION_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
        if (!mr[i]) {
            fprintf(stderr, "Failed to register memory region %d\n", i);
            return 1;
        }
    }

    printf("Successfully registered %d memory regions of size %d bytes each.\n", NUM_REGIONS, REGION_SIZE);

    // 在这里执行RDMA操作
    // ...

    // 取消注册内存区域并释放资源
    for (i = 0; i < NUM_REGIONS; i++) {
        ibv_dereg_mr(mr[i]);
        free(regions[i]);
    }

    ibv_dealloc_pd(pd);
    ibv_close_device(context);
    ibv_free_device_list(dev_list);

    printf("Resources have been freed.\n");

    return 0;
}