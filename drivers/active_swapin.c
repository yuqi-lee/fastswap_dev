#include "active_swapin.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/pid.h>
#include <linux/pgtable.h>
#include <linux/swap.h>

// 检查页面是否被换出，如果是，则将其换入
int check_and_swapin_page(unsigned long addr, pte_t *pte, struct mm_struct *mm, struct vm_area_struct *vma) {
    if (pte_none(*pte)) {
        pr_info("Page at address 0x%lx is not present (swap entry).\n", addr);
        return -1; // 页表项不存在
    }

    if (!pte_present(*pte)) {
        // 页面被换出，处理swap
        swp_entry_t entry = pte_to_swp_entry(*pte);

        if (!is_swap_pte(*pte)) {
            pr_info("Page at address 0x%lx is not a swap entry.\n", addr);
            return -1; // 不是有效的swap entry
        }

        pr_info("Swapped out page at address 0x%lx, swapping it in...\n", addr);

        // 尝试将页面换入
        struct page *page = swapin_readahead(entry, GFP_KERNEL, mm, addr, vma);
        if (!page) {
            pr_err("Failed to swap in page at address 0x%lx\n", addr);
            return -1; // 换入失败
        }

        set_pte_at(mm, addr, pte, mk_pte(page, vma->vm_page_prot));

        pr_info("Successfully swapped in page at address 0x%lx\n", addr);
        return 0; // 换入成功
    }

    pr_info("Page at address 0x%lx is already present in memory.\n", addr);
    return 0; // 页面已经存在，无需换入
}

// 页表扫描回调函数
void my_pte_callback(unsigned long addr, pte_t *pte, struct mm_struct *mm, struct vm_area_struct *vma) {
    check_and_swapin_page(addr, pte, mm, vma);
}

// 遍历页表的线程安全函数
void scan_page_table(struct task_struct *task, pte_callback_t callback) {
    struct mm_struct *mm = task->mm;
    struct vm_area_struct *vma;
    unsigned long addr;

    down_read(&mm->mmap_lock); // 加锁防止并发修改

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        // 遍历VMA区域内的页表
        for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
            pgd_t *pgd = pgd_offset(mm, addr);
            if (pgd_none(*pgd) || pgd_bad(*pgd))
                continue;

            pud_t *pud = pud_offset(pgd, addr);
            if (pud_none(*pud) || pud_bad(*pud))
                continue;

            pmd_t *pmd = pmd_offset(pud, addr);
            if (pmd_none(*pmd) || pmd_bad(*pmd))
                continue;

            if (pmd_huge(*pmd)) {
                // 大页处理
                continue;
            }

            pte_t *pte;
            spinlock_t *ptl = pte_lockptr(mm, pmd);  // 获取PTE锁
            spin_lock(ptl);                          // 加锁

            pte = pte_offset_map(pmd, addr);
            if (!pte) {
                spin_unlock(ptl);                    // 解锁
                continue;
            }

            // 调用回调函数处理找到的PTE
            callback(addr, pte, mm, vma);

            pte_unmap(pte);
            spin_unlock(ptl);                        // 解锁
        }
    }

    up_read(&mm->mmap_lock); // 解锁
}

// 内核模块的入口
static int __init my_module_init(void) {
    struct pid *pid_struct;
    struct task_struct *task;
    pid_t pid = 1234; // 替换为目标进程的PID

    // 根据PID获取task_struct
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        pr_err("Failed to find PID: %d\n", pid);
        return -ESRCH;
    }

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        pr_err("Failed to find task for PID: %d\n", pid);
        return -ESRCH;
    }

    // 扫描指定进程的页表
    scan_page_table(task, my_pte_callback);

    return 0;
}

// 内核模块的退出
static void __exit my_module_exit(void) {
    pr_info("Module unloaded.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Thread-Safe Page Table Scanner with Swap In Capability");

