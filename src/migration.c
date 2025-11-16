// move_page_probe_5_3_1.c
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/migrate.h>
#include <linux/swap.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/pagemap.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Farhan Tanvir Utshaw");
MODULE_DESCRIPTION("kprobe: attempt migrating first file-backed page for inode 1866171 on Linux 5.3.1");

/* ----- CONFIG ----- */
//get rid of inode
static const unsigned long target_inode = 1866171UL;
static int target_node = 1; /* change if you want another destination node */

/* ----- Prototypes for symbols that may be internal on some kernels.
   If you exported these in your kernel build, these declarations
   allow this module to compile and link against them. If you did NOT
   export them, linking will fail — use migratepage path. ----- */


   //export these functions into the kernel
   //get rid of i node
extern int isolate_lru_page(struct page *page) __attribute__((weak));
extern void putback_lru_page(struct page *page) __attribute__((weak));
extern int migrate_page_move_mapping(struct address_space *mapping,
                                     struct page *newpage, struct page *page,
                                     int mode) __attribute__((weak));
/* Note: mapping->a_ops->migratepage() will be used preferentially when present. */

/* ----- Globals ----- */
static atomic_t did_move = ATOMIC_INIT(0);
static struct kprobe kp;

/* x86_64 first arg extraction */
static inline struct page *get_page_arg(struct pt_regs *regs)
{
#if defined(CONFIG_X86_64)
    return (struct page *)regs->di;
#else
    #error "Unsupported arch in this module"
#endif
}

static void dump_page_info(struct page *page)
{
    pr_info("page=%p pfn=%lu flags=0x%lx refcount=%d mapcount=%d LRU=%d Movable=%d Unevictable=%d Anon=%d File=%d Uptodate=%d Dirty=%d Writeback=%d Mlocked=%d Compound=%d Head=%d\n",
            page,
            page_to_pfn(page),
            page->flags,
            page_ref_count(page),
            page_mapcount(page),
            PageLRU(page),
            PageMovable(page),
            PageUnevictable(page),
            PageAnon(page),
            PageSwapBacked(page) ? 0 : 1,
            PageUptodate(page),
            PageDirty(page),
            PageWriteback(page),
            PageMlocked(page),
            PageCompound(page),
            PageHead(page));
}

/* Attempt migration using mapping->a_ops->migratepage if available,
   otherwise (if weak symbols exported in kernel) try isolate + migrate_page_move_mapping. */
static void try_migrate_page(struct page *page)
{
    struct address_space *mapping;
    struct inode *inode;
    struct page *newpage = NULL;
    unsigned long old_pfn;
    int rc = -EINVAL;
    int retry;

    if (!page || atomic_read(&did_move))
        return;

    mapping = page_mapping(page);
    if (!mapping) {
        pr_info("skip %p: no mapping (not file-backed)\n", page);
        return;
    }
    inode = mapping->host;
    if (!inode) {
        pr_info("skip %p: mapping has no inode\n", page);
        return;
    }

    /* only act on the requested inode */
    if (inode->i_ino != target_inode)
        return;

    /* diagnostics */
    dump_page_info(page);
    pr_info("inode=%lu mapping=%p a_ops=%p migratepage=%p\n",
            inode->i_ino,
            mapping,
            mapping->a_ops,
            mapping->a_ops ? mapping->a_ops->migratepage : NULL);

    /* basic candidate checks */
    if (!PageLRU(page)) {
        pr_info("Skipping: not on LRU\n");
        return;
    }
    if (PageUnevictable(page)) {
        pr_info("Skipping: unevictable\n");
        return;
    }
    if (PageAnon(page)) {
        pr_info("Skipping: anonymous\n");
        return;
    }

    /* must not be mapped in userspace for page-cache-only candidate */
    if (page_mapcount(page) != 0) {
        pr_info("Skipping: mapcount != 0 (mapped userspace?) mapcount=%d\n", page_mapcount(page));
        return;
    }

    pr_info("counts: page_count=%d mapcount=%d writeback=%d dirty=%d locked=%d\n",
            page_count(page), page_mapcount(page),
            PageWriteback(page), PageDirty(page), PageLocked(page));

    old_pfn = page_to_pfn(page);

    /* First, try the safe exported callback if present */
    if (mapping->a_ops && mapping->a_ops->migratepage) {
        pr_info("Attempting migration via mapping->a_ops->migratepage()\n");

        newpage = alloc_pages_node(target_node, GFP_KERNEL | __GFP_MOVABLE, 0);
        if (!newpage) {
            pr_info("alloc_pages_node(node=%d) failed\n", target_node);
            return;
        }

        /* mapping->a_ops->migratepage returns 0 on success usually */
        rc = mapping->a_ops->migratepage(mapping, newpage, page, MIGRATE_SYNC);

        if (rc == 0) {
            pr_info("migratepage() SUCCESS: inode=%lu old_pfn=%lu new_pfn=%lu\n",
                    inode->i_ino, old_pfn, page_to_pfn(newpage));
            atomic_set(&did_move, 1);
            unregister_kprobe(&kp);
            /* ownership: often migratepage takes ownership of newpage or sets it up;
               do not free newpage here. */
            return;
        } else {
            pr_info("mapping->a_ops->migratepage() returned rc=%d; freeing newpage and aborting this attempt\n", rc);
            __free_pages(newpage, 0);
            /* fall through to try lower-level path only if we have exported helpers */
        }
    }

    /* If we reach here, mapping->a_ops->migratepage either not present or failed.
       If the kernel exported isolate_lru_page/migrate_page_move_mapping, try low-level route. */
    if (isolate_lru_page && migrate_page_move_mapping && putback_lru_page) {
        pr_info("Attempting lower-level migration path using isolate_lru_page()/migrate_page_move_mapping()\n");

        /* Try isolating page with retries for transient -EAGAIN */
        for (retry = 0; retry < 5; retry++) {
            rc = isolate_lru_page(page);
            if (rc == 0)
                break;
            if (rc == -EAGAIN) {
                msleep(1);
                continue;
            }
            pr_info("isolate_lru_page() rc=%d attempt=%d\n", rc, retry);
            msleep(1);
        }
        if (rc) {
            pr_info("Failed to isolate page pfn=%lu rc=%d\n", old_pfn, rc);
            return;
        }
        pr_info("isolate_lru_page() success pfn=%lu\n", old_pfn);

        newpage = alloc_pages_node(target_node, GFP_KERNEL | __GFP_MOVABLE, 0);
        if (!newpage) {
            pr_info("alloc_pages_node(node=%d) failed\n", target_node);
            putback_lru_page(page);
            return;
        }

        for (retry = 0; retry < 5; retry++) {
            rc = migrate_page_move_mapping(mapping, newpage, page, 0);
            if (rc == 0)
                break;
            if (rc == -EAGAIN) {
                msleep(1);
                continue;
            }
            pr_info("migrate_page_move_mapping() rc=%d attempt=%d\n", rc, retry);
            break;
        }

        if (rc == 0) {
            pr_info("migrate_page_move_mapping SUCCESS: old_pfn=%lu new_pfn=%lu\n",
                    old_pfn, page_to_pfn(newpage));
            atomic_set(&did_move, 1);
            unregister_kprobe(&kp);
            return;
        }

        pr_info("migrate_page_move_mapping FAILED rc=%d; cleaning up\n", rc);
        putback_lru_page(page);
        __free_pages(newpage, 0);
        return;
    }

    pr_info("No viable migration path available (mapping->a_ops->migratepage missing/failed and no exported low-level helpers)\n");
}

/* kprobe pre handler */
static int my_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    struct page *page;

    if (atomic_read(&did_move))
        return 0;

    page = get_page_arg(regs);
    if (!page)
        return 0;

    try_migrate_page(page);
    return 0;
}

/* module init/exit */
static int __init move_single_page_init(void)
{
    int ret;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = "mark_page_accessed";
    kp.pre_handler = my_pre_handler;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed: %d\n", ret);
        return ret;
    }

    pr_info("kprobe registered on %s; watching inode=%lu\n", kp.symbol_name, target_inode);
    return 0;
}

static void __exit move_single_page_exit(void)
{
    if (!atomic_read(&did_move)) {
        unregister_kprobe(&kp);
    }
    pr_info("module exit; did_move=%d\n", atomic_read(&did_move));
}

module_init(move_single_page_init);
module_exit(move_single_page_exit);


//atoomic handler tracks if it has moved a single page