#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>
#include <linux/kernel.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
#include "extended_entry_allocator.h"



void page_queue_delete(void) {
    //vunmap(queue_allocator);
    //vunmap(queue_deallocator);
}
EXPORT_SYMBOL(page_queue_delete);

static int __init extended_entry_allocator_init_module(void) {
    return 0;
}

static void __exit extended_entry_allocator_cleanup_module(void) {
    page_queue_delete();
}

module_init(extended_entry_allocator_init_module);
module_exit(extended_entry_allocator_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Remote Page Allocator");