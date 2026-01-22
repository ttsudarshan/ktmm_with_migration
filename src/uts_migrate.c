// mm/uts_promote.c  (Linux 5.14)
// Add to mm/Makefile: obj-y += uts_promote.o
//
// Debug version: NO ratelimiting (uses pr_info everywhere)
 
#include <linux/mm.h>
#include <linux/migrate.h>
#include <linux/pagemap.h>
#include <linux/memcontrol.h>
#include <linux/swap.h>
#include <linux/gfp.h>
#include <linux/node.h>
#include <linux/page_ref.h>   // page_count()
#include <linux/printk.h>
 
#include "internal.h"
 
static struct page *uts_alloc_migrate_page(struct page *page, unsigned long private)
{
	int nid = (int)private;
	struct page *newp;
 
	/* Allocate destination page on the target node */
	newp = alloc_pages_node(nid, GFP_HIGHUSER_MOVABLE | __GFP_THISNODE, 0);
 
 
	return newp;
}
 
static void uts_free_migrate_page(struct page *page, unsigned long private)
{
	__free_pages(page, 0);
}
 
/*
 * Returns:
 *   0 on success (page migrated)
 *   >0: number of pages that failed (for this single-page call: typically 1)
 *   <0: -errno
 */
int uts_migrate_one_file_page(struct page *page, int target_nid)
{
	unsigned long src_pfn = page_to_pfn(page);
 
 
 
	LIST_HEAD(plist);
	int ret;
 
	if (!page) {
		pr_info("uts: MIG start page=NULL\n");
		return -EINVAL;
	}
 
	/* Quick filter (keep your original) */
	if (PageAnon(page) || PageCompound(page)) {
		pr_info("uts: MIG start REJECT pfn=%lu anon=%d compound=%d src=%d dst=%d\n",
			(unsigned long)src_pfn,
			PageAnon(page), PageCompound(page),
			page_to_nid(page), target_nid);
		return -EINVAL;
	}
 
 
	/* 1) Isolate the page */
	ret = isolate_lru_page(page);
	if (ret) {
 
 
		return ret;
	}
 
	/*
	 * 2) Secret sauce:
	 * - Caller provides an extra ref.
	 * - isolate_lru_page() added one ref.
	 * - Drop caller’s extra ref so migrate_pages sees only the isolate ref.
	 */
	put_page(page);
 
 
	/* Put into list for migrate_pages */
	list_add(&page->lru, &plist);
 
	/* 3) Migrate */
	ret = migrate_pages(&plist,
			    uts_alloc_migrate_page,
			    uts_free_migrate_page,
			    (unsigned long)target_nid,
			    MIGRATE_SYNC,
			    MR_NUMA_MISPLACED);
 
 
 
 
	/* 4) Anything left in plist failed migration */
	if (!list_empty(&plist)) {
		struct page *p, *n;
 
		list_for_each_entry_safe(p, n, &plist, lru) {
 
 
 
			list_del(&p->lru);
			putback_lru_page(p);
		}
	} 
 
	return ret;
}
EXPORT_SYMBOL_GPL(uts_migrate_one_file_page);
 
int uts_migrate_file_pages_bulk_vec(struct page **pages, int nr_pages, int target_nid)
{
	LIST_HEAD(plist);
	int i, ret, n_isolated = 0;
 
	if (!pages || nr_pages <= 0)
		return -EINVAL;
 
	/*
	 * Contract:
	 *  - Caller provides ONE extra ref per page (the promote-set pin).
	 *  - For any page we successfully isolate, we CONSUME that caller ref
	 *    via put_page(page) (same as single-page helper).
	 *  - For any page we do NOT isolate (filter or isolate_lru_page fails),
	 *    we do NOT consume the caller ref, and we leave pages[i] non-NULL
	 *    so caller can put_page().
	 *  - For pages we do isolate, we set pages[i] = NULL (caller must not touch).
	 */
	for (i = 0; i < nr_pages; i++) {
		struct page *page = pages[i];
		int r;
 
		if (!page)
			continue;
 
		/* Same quick filters as single-page helper */
		if (PageAnon(page) || PageCompound(page) || !page_mapping(page))
			continue;
 
		r = isolate_lru_page(page);
		if (r)
			continue;
 
		/*
		 * Consume caller-provided extra ref.
		 * isolate_lru_page() added one ref, we keep that one for migration.
		 */
		put_page(page);
 
		/* After isolation, it's safe to use page->lru for our local list */
		list_add_tail(&page->lru, &plist);
		pages[i] = NULL; /* mark as consumed / do not touch in caller */
		n_isolated++;
	}
 
	if (!n_isolated)
		return 0;
 
	ret = migrate_pages(&plist,
			    uts_alloc_migrate_page,
			    uts_free_migrate_page,
			    (unsigned long)target_nid,
			    MIGRATE_SYNC,
			    MR_NUMA_MISPLACED);
 
	/* Any leftovers failed: put them back (this consumes the isolate ref) */
	if (!list_empty(&plist)) {
		struct page *p, *n;
 
		list_for_each_entry_safe(p, n, &plist, lru) {
			list_del_init(&p->lru);
			putback_lru_page(p);
		}
	}
 
	return ret;
}
EXPORT_SYMBOL_GPL(uts_migrate_file_pages_bulk_vec);
