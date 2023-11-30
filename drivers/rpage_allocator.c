#include "rpage_allocator.h"

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>


int cpu_cache_init(void) {
    struct path path_;
    struct address_space *addr_space_;
    struct page *page_;
    struct page **pages_ = NULL;
    void **slot_;
    int i = 0;

    if (kern_path("/dev/shm/cpu_cache", LOOKUP_FOLLOW, &path_) != 0) {
        // handle error
    }

    addr_space_ = path.dentry->d_inode->i_mapping;

    pages_ = (struct page **) vmalloc(sizeof(struct page *) * addr_space_->nrpages);
    if(pages_ == NULL) {
        pr_err("Bad alloc for pages_(struct page**)\n");
        return -1;
    }
    radix_tree_for_each_slot(slot, &addr_space_->i_pages, &iter, 0) {
        page_ = radix_tree_deref_slot(slot);
        // do something with page
        pages_[i] = page_;
    }

    cpu_cache_ = (struct cpu_cache_storage *) vmap(pages_, addr_space_->nrpages, VM_MAP | VM_ALLOC, 0);
    if(cpu_cache_ == NULL) {
        pr_err("Bad v-mapping for cpu_cache_\n");
        vfree(pages_);
        return -1;
    }

    vfree(pages_);
    return 0;
}

u64 alloc_remote_page(void) {
    list_for_each_entry()
}