#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

#define __NR_hello_syscall 449

int main() {
    const char *path = "/mydata/swapfile2";
    long int ret = syscall(__NR_hello_syscall, path);
    if (ret == 0)
        printf("System call executed successfully.\n");
    else
        printf("System call failed with error code %ld\n", ret);

    return 0;
}

