#include "fastswap.c"

#include <linux/type.h>

struct process_info {
    pid_t pid;
    struct rhash_head process_info_rhash;
};

struct rhashtable_params process_map_params = {
    .head_offset = offsetof(struct process_info, process_info_rhash),
    .key_offset = offsetof(struct process_info, pid),
    .key_len = sizeof(((struct process_info *)0)->pid),
    .hashfn = jhash,
};