#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>

#define ALLOCATE_BUFFER_SIZE (128 << 10) // 512 MB
#define DEALLOCATE_BUFFER_SIZE (512 << 10) // 2 GB

struct allocator_page_queue {
    u32 rkey;
    u64 begin;
    u64 end;
    u64 pages[ALLOCATE_BUFFER_SIZE];
};

struct deallocator_page_queue {
    u64 begin;
    u64 end;
    u64 pages[DEALLOCATE_BUFFER_SIZE];
};

struct allocator_page_queue *queue_allocator = NULL;
struct deallocator_page_queue *queue_deallocator = NULL;


u64 get_length_allocator(void);
u64 pop_queue_allocator(void);
int push_queue_allocator(u64 page_addr);

u64 get_length_deallocator(void);
u64 pop_queue_deallocator(void);
int push_queue_deallocator(u64 page_addr);