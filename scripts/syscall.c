#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_hello_syscall 449

int main() {
    int value = 1; // 传递给系统调用的参数值
    long int ret = syscall(__NR_hello_syscall, value);
    if (ret == 0)
        printf("System call executed successfully.\n");
    else
        printf("System call failed with error code %ld\n", ret);

    return 0;
}

