#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/shmem_fs.h>
#include "extended_entry_allocator.h"

int allocator_page_queue_init(void) {
    struct path path_;
    struct address_space *addr_space_;
    struct page *page_;
    struct page **pages_ = NULL;
    void **slot_;
    struct radix_tree_iter iter_;
    int i = 0;
    int ret;

    ret = kern_path("/dev/shm/allocator_page_queue", LOOKUP_FOLLOW, &path_);
    if (ret != 0) {
        // handle error
        pr_err("debug: cannot find /allocator_page_queue_init with error code %d\n", ret);
        return -1;
    }

    addr_space_ = path_.dentry->d_inode->i_mapping;
    if(addr_space_ == NULL) {
        pr_err("cannot get address space\n");
        return -1;
    }
    pr_info("num of pages: %ld\n", addr_space_->nrpages);

    pages_ = (struct page **) kmalloc(sizeof(struct page *) * addr_space_->nrpages, GFP_KERNEL);
    if(pages_ == NULL) {
        pr_err("Bad alloc for pages_(struct page**)\n");
        return -1;
    }
    
    radix_tree_iter_init(&iter_, 0);
    radix_tree_for_each_slot(slot_, &addr_space_->i_pages, &iter_, 0) {
        page_ = radix_tree_deref_slot(slot_);
        // do something with page
        pages_[i] = page_;
        pr_info("%d page ptr: %p\n", i, pages_[i]);
        i++;
    }

    if(i != addr_space_->nrpages) {
        pr_info("i != nrpages\n");
    } else {
        pr_info("i == nrpages\n");
    }
    // return 0;

    queue_allocator = (struct allocator_page_queue *) vmap(pages_, addr_space_->nrpages, VM_MAP, PAGE_KERNEL);
    if(queue_allocator == NULL) {
        pr_err("Bad v-mapping for allocator_page_queue\n");
        kfree(pages_);
        return -1;
    }

    pr_info("allocator_page_queue address is %p\n", (void*)queue_allocator);

    kfree(pages_);
    return 0;
}
EXPORT_SYMBOL(allocator_page_queue_init);

int deallocator_page_queue_init(void) {
    struct path path_;
    struct address_space *addr_space_;
    struct page *page_;
    struct page **pages_ = NULL;
    void **slot_;
    struct radix_tree_iter iter_;
    int i = 0;
    int ret;

    ret = kern_path("/dev/shm/deallocator_page_queue_init", LOOKUP_FOLLOW, &path_);
    if (ret != 0) {
        // handle error
        pr_err("debug: cannot find /deallocator_page_queue_init with error code %d\n", ret);
        return -1;
    }

    addr_space_ = path_.dentry->d_inode->i_mapping;
    if(addr_space_ == NULL) {
        pr_err("cannot get address space\n");
        return -1;
    }
    pr_info("num of pages: %ld\n", addr_space_->nrpages);

    pages_ = (struct page **) kmalloc(sizeof(struct page *) * addr_space_->nrpages, GFP_KERNEL);
    if(pages_ == NULL) {
        pr_err("Bad alloc for pages_(struct page**)\n");
        return -1;
    }
    
    radix_tree_iter_init(&iter_, 0);
    radix_tree_for_each_slot(slot_, &addr_space_->i_pages, &iter_, 0) {
        page_ = radix_tree_deref_slot(slot_);
        // do something with page
        pages_[i] = page_;
        pr_info("%d page ptr: %p\n", i, pages_[i]);
        i++;
    }

    if(i != addr_space_->nrpages) {
        pr_info("i != nrpages\n");
    } else {
        pr_info("i == nrpages\n");
    }
    // return 0;

    queue_deallocator = (struct deallocator_page_queue *) vmap(pages_, addr_space_->nrpages, VM_MAP, PAGE_KERNEL);
    if(queue_deallocator == NULL) {
        pr_err("Bad v-mapping for deallocator_page_queue\n");
        kfree(pages_);
        return -1;
    }

    pr_info("deallocator_page_queue address is %p\n", (void*)queue_deallocator);

    kfree(pages_);
    return 0;
}
EXPORT_SYMBOL(deallocator_page_queue_init);


u64 get_length_allocator(void) {
    u64 begin = queue_allocator->begin;
    u64 end = queue_allocator->end;
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (ALLOCATE_BUFFER_SIZE - begin + end);
    }
}
EXPORT_SYMBOL(get_length_allocator);

u64 pop_queue_allocator(void) {
    u64 ret = 0;
    u64 prev_begin;
    while(get_length_allocator() == 0) ;
    prev_begin = queue_allocator->begin;
    queue_allocator->begin = (queue_allocator->begin + 1) % ALLOCATE_BUFFER_SIZE;
    while(queue_allocator->pages[prev_begin] == 0) ;
    ret = queue_allocator->pages[prev_begin];
    queue_allocator->pages[prev_begin] = 0;
    return ret;
}
EXPORT_SYMBOL(pop_queue_allocator);

int push_queue_allocator(u64 page_addr) {
    return 0;
}

u64 get_length_deallocator(void) {
    u64 begin = queue_deallocator->begin;
    u64 end = queue_deallocator->end;
    if (begin == end) {
        return 0;
    }
    if (end > begin) {
        return (end - begin);
    } else {
        return (DEALLOCATE_BUFFER_SIZE - begin + end);
    }
}
EXPORT_SYMBOL(get_length_deallocator);

u64 pop_queue_deallocator(void) {
    return 0;
}

int push_queue_deallocator(u64 page_addr) {
    int ret = 0;
    u64 prev_end = queue_deallocator->end;
    while(get_length_deallocator() == DEALLOCATE_BUFFER_SIZE - 1) ;
    queue_deallocator->end = (queue_deallocator->end + 1) % DEALLOCATE_BUFFER_SIZE;
    queue_deallocator->pages[prev_end] = page_addr;
    return ret;
}
EXPORT_SYMBOL(push_queue_deallocator);

void page_queue_delete(void) {
    vunmap(queue_allocator);
    vunmap(queue_deallocator);
}
EXPORT_SYMBOL(page_queue_delete);

static int __init extended_entry_allocator_init_module(void) {
    int ret = 0;

    ret = allocator_page_queue_init();
    if (ret) {
        pr_err("allocator_page_queue init failed\n");
        return ret;
    }

    ret = deallocator_page_queue_init();
    if (ret) {
        pr_err("deallocator_page_queue init failed\n");
        return ret;
    }

    return 0;
}

static void __exit extended_entry_allocator_cleanup_module(void) {
    page_queue_delete();
}

module_init(extended_entry_allocator_init_module);
module_exit(extended_entry_allocator_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Remote Page Allocator");