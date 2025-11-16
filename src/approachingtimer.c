/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 */

//#define pr_fmt(fmt) "[ KTMM Mod ] vmscan - " fmt

#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/buffer_head.h>
#include <linux/cgroup.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/hashtable.h> //***
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/memcontrol.h>
//#include <linux/mmflags.h>
#include <linux/mmzone.h>
#include <linux/mm_inline.h>
#include <linux/migrate.h>
#include <linux/migrate_mode.h>
#include <linux/nodemask.h>
#include <linux/numa.h>
#include <linux/page-flags.h>
#include <linux/page_ref.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/printk.h>
#include <linux/rmap.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include "ktmm_hook.h"
#include "ktmm_vmscan.h"

// possibly needs to be GFP_USER?
#define TMEMD_GFP_FLAGS GFP_NOIO

// which node is the pmem node
int pmem_node = -1;

/* holds pointers to the tmemd daemons running per node */
static struct task_struct *tmemd_list[MAX_NUMNODES];


/* per node tmemd wait queues */
wait_queue_head_t tmemd_wait[MAX_NUMNODES];

/* Track printk overhead to exclude from scan timing */
static s64 g_printk_overhead_ns = 0;


/************** MISC HOOKED FUNCTION PROTOTYPES *****************************/
static struct mem_cgroup *(*pt_mem_cgroup_iter)(struct mem_cgroup *root,
				struct mem_cgroup *prev,
				struct mem_cgroup_reclaim_cookie *reclaim);


static bool (*pt_zone_watermark_ok_safe)(struct zone *z,
					unsigned int order,
					unsigned long mark,
					int highest_zoneidx);


static struct pglist_data *(*pt_first_online_pgdat)(void);


static struct zone *(*pt_next_zone)(struct zone *zone);


static void (*pt_free_unref_page_list)(struct list_head *list);


static void (*pt_lru_add_drain)(void);


static void (*pt_cgroup_update_lru_size)(struct lruvec *lruvec, enum lru_list lru,
					int zid, int nr_pages);


static void (*pt_cgroup_uncharge_list)(struct list_head *page_list);


static unsigned long (*pt_isolate_lru_folios)(unsigned long nr_to_scan, struct lruvec *lruvec,
					struct list_head *dst, unsigned long *nr_scanned,
					struct scan_control *sc, enum lru_list lru);


static unsigned int (*pt_move_folios_to_lru)(struct lruvec *lruvec, struct list_head *list);


static void (*pt_folio_putback_lru)(struct folio *folio);


static int (*pt_folio_referenced)(struct folio *folio, int is_locked,
				struct mem_cgroup *memcg, unsigned long *vm_flags);


static unsigned long (*pt_node_page_state)(struct pglist_data *pgdat, enum node_stat_item item);


/* __alloc_pages (page_alloc.c) */
/* probably needs removed */
static struct page *(*pt_alloc_pages)(gfp_t gfp_mask, unsigned int order, int preferred_nid,
					nodemask_t *nodemask);


/**************** KTMM IMPLEMENTATION OF HOOKED FUNCTION **********************/
static struct mem_cgroup *ktmm_mem_cgroup_iter(struct mem_cgroup *root,
				struct mem_cgroup *prev,
				struct mem_cgroup_reclaim_cookie *reclaim)
{
	return pt_mem_cgroup_iter(root, prev, reclaim);
}


static bool ktmm_zone_watermark_ok_safe(struct zone *z,
					unsigned int order,
					unsigned long mark,
					int highest_zoneidx)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_zone_watermark_ok_safe(z, order, mark, highest_zoneidx);
}


static struct pglist_data *ktmm_first_online_pgdat(void)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_first_online_pgdat();
}


static struct zone *ktmm_next_zone(struct zone *zone)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_next_zone(zone);
}


static void ktmm_free_unref_page_list(struct list_head *list)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_free_unref_page_list(list);
}


static void ktmm_lru_add_drain(void)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	pt_lru_add_drain();
}


static void ktmm_cgroup_update_lru_size(struct lruvec *lruvec, enum lru_list lru,
					int zid, int nr_pages)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	pt_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
}


static void ktmm_cgroup_uncharge_list(struct list_head *page_list)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	pt_cgroup_uncharge_list(page_list);
}


static unsigned long ktmm_isolate_lru_folios(unsigned long nr_to_scan, struct lruvec *lruvec,
					struct list_head *dst, unsigned long *nr_scanned,
					struct scan_control *sc, enum lru_list lru)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_isolate_lru_folios(nr_to_scan, lruvec, dst, nr_scanned, sc, lru);
}


static unsigned int ktmm_move_folios_to_lru(struct lruvec *lruvec, struct list_head *list)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_move_folios_to_lru(lruvec, list);
}


static void ktmm_folio_putback_lru(struct folio *folio)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	pt_folio_putback_lru(folio);
}


static int ktmm_folio_referenced(struct folio *folio, int is_locked,
				struct mem_cgroup *memcg, unsigned long *vm_flags)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_folio_referenced(folio, is_locked, memcg, vm_flags);
}


static unsigned long ktmm_node_page_state(struct pglist_data *pgdat, enum node_stat_item item)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return pt_node_page_state(pgdat, item);
}

/**
 * populate_lru_for_testing - allocate test pages and add them to LRU lists
 * 
 * @pgdat:	node data struct
 * @nr_pages:	number of pages to allocate per LRU list
 * 
 * This function allocates test pages and adds them to the LRU lists so that
 * scanning can actually find pages to scan. Without this, LRU lists may be
 * empty and scanning will report 0 pages.
 */
static int populate_lru_for_testing(struct pglist_data *pgdat, int nr_pages)
{
	int i, lru;
	struct page *page;
	struct lruvec *lruvec;
	int total_allocated = 0;
	
	printk(KERN_INFO "Populating LRU lists with test pages for node %d\n", pgdat->node_id);
	
	lruvec = &pgdat->__lruvec;
	
	/* Allocate pages for each evictable LRU list */
	for_each_evictable_lru(lru) {
		int allocated = 0;
		
		for (i = 0; i < nr_pages; i++) {
			/* Allocate a page */
			page = alloc_page(GFP_KERNEL);
			if (!page) {
				printk(KERN_WARNING "Failed to allocate test page %d for LRU %d\n", i, lru);
				break;
			}
			
			/* Initialize page flags */
			get_page(page);  // Increment refcount
			SetPageLRU(page);
			
			/* Set appropriate flags based on LRU type */
			if (lru == LRU_ACTIVE_ANON || lru == LRU_ACTIVE_FILE) {
				SetPageActive(page);
			} else {
				ClearPageActive(page);
			}
			
			if (lru == LRU_ACTIVE_ANON || lru == LRU_INACTIVE_ANON) {
				SetPageSwapBacked(page);
			} else {
				ClearPageSwapBacked(page);
			}
			
			/* Add to LRU list */
			spin_lock_irq(&lruvec->lru_lock);
			list_add_tail(&page->lru, &lruvec->lists[lru]);
			__mod_node_page_state(pgdat, NR_LRU_BASE + lru, 1);
			spin_unlock_irq(&lruvec->lru_lock);
			
			allocated++;
		}
		
		printk(KERN_INFO "  Allocated %d pages for LRU %d\n", allocated, lru);
		total_allocated += allocated;
	}
	
	printk(KERN_INFO "Total test pages allocated: %d\n", total_allocated);
	return total_allocated;
}

/**
 * free_test_pages_from_lru - free all test pages from LRU lists
 * 
 * @pgdat:	node data struct
 * 
 * This function frees all test pages that were added to the LRU lists
 * during testing to prevent memory leaks.
 */
static void free_test_pages_from_lru(struct pglist_data *pgdat)
{
	struct lruvec *lruvec;
	struct page *page, *next;
	int lru;
	int freed = 0;
	
	printk(KERN_INFO "Freeing test pages from node %d\n", pgdat->node_id);
	
	lruvec = &pgdat->__lruvec;
	
	spin_lock_irq(&lruvec->lru_lock);
	
	/* Free pages from all LRU lists */
	for_each_lru(lru) {
		list_for_each_entry_safe(page, next, &lruvec->lists[lru], lru) {
			list_del(&page->lru);
			ClearPageLRU(page);
			__mod_node_page_state(pgdat, NR_LRU_BASE + lru, -1);
			freed++;
			put_page(page);
			__free_page(page);
		}
	}
	
	spin_unlock_irq(&lruvec->lru_lock);
	
	printk(KERN_INFO "Freed %d test pages\n", freed);
}

/*****************************************************************************
 * Page Access Tracking Helper Functions
 *****************************************************************************/

/**
 * track_folio_access - track if folio was previously accessed
 * 
 * Hybrid approach: Print only ACCESSED pages, measure printk overhead
 */
/* Phase 1: Clear all reference bits BEFORE scanning */
static void clear_all_reference_bits(struct pglist_data *pgdat)
{
    struct page *page;
    struct folio *folio;
    unsigned long pfn;
    
    for (pfn = pgdat->node_start_pfn; 
         pfn < pgdat->node_start_pfn + pgdat->node_spanned_pages; 
         pfn++) {
        if (!pfn_valid(pfn)) continue;
        
        page = pfn_to_page(pfn);
        folio = page_folio(page);
        
        if (folio_test_lru(folio)) {
            folio_clear_referenced(folio);
        }
    }
}

/* Phase 2: Scan and track (without clearing!) */
static int track_folio_access(struct folio *folio, struct pglist_data *pgdat, const char *location)
{
    int was_accessed;
    const char *node_type = (pgdat->pm_node == 0) ? "DRAM" : "PMEM";
    ktime_t printk_start, printk_end;
    s64 printk_duration;
    
    /* Check the referenced flag WITHOUT clearing it */
    was_accessed = folio_test_referenced(folio);

    if (was_accessed) {
        printk_start = ktime_get();
        
        printk(KERN_INFO "*** ACCESSED at %s: referenced_bit=1 (folio=%p, node=%s, jiffies=%lu) ***\n", 
                 location, folio, node_type, jiffies);
        
        printk_end = ktime_get();
        printk_duration = ktime_to_ns(ktime_sub(printk_end, printk_start));
        g_printk_overhead_ns += printk_duration;
        
        /* DON'T clear here - we're just measuring! */
        /* folio_clear_referenced(folio); */  // REMOVE THIS LINE
    }
    
    return was_accessed;
}
/*****************************************************************************
 * ALLOC & SWAP
 *****************************************************************************/

/**
 * alloc_pmem_page - allocate a page on pmem node
 *
 * @page:	single page
 * @data:	misc data
 *
 * This is to be fed into migrate_pages() as a parameter.
 */
struct page* alloc_pmem_page(struct  page *page, unsigned long data)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);
	gfp_t gfp_mask = GFP_USER | __GFP_PMEM;
	return alloc_page(gfp_mask);
}


/**
 * alloc_normal_page - allocate a page on a normal node
 *
 * @page:	single page
 * @data:	misc data
 *
 * This is to be fed into migrate_pages() as a parameter.
 */
struct page* alloc_normal_page(struct page *page, unsigned long data)
{
        gfp_t gfp_mask = GFP_USER;
        return alloc_page(gfp_mask);
}

/* probably needs removed */
static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
					nodemask_t *nodemask)
{
	//node mask of pmem_node
	//pass node mask into alloc pages
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	nodemask_t nodemask_test;
	int nid;
	
	if ((gfp_mask & __GFP_PMEM) !=0) {

		for_each_node_state(nid, N_MEMORY) {
			if(NODE_DATA(nid)->pm_node != 0)
				node_set(nid, nodemask_test);
			else
				node_clear(nid, nodemask_test);
		}

		nodemask = &nodemask_test;
	}
	else if ((gfp_mask & __GFP_PMEM) == 0 && pmem_node_id != -1) {

		for_each_node_state(nid, N_MEMORY) {
			if (NODE_DATA(nid)->pm_node == 0)
				node_set(nid, nodemask_test);
			else
				node_clear(nid, nodemask_test);
		}

		nodemask = &nodemask_test;
	}
	return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);
}


/*****************************************************************************
 * Node Scanning, Shrinking, and Promotion
 *****************************************************************************/

/**
 * ktmm_cgroup_below_low - if memory cgroup is below low memory thresh
 *
 * @memcg:	memory cgroup
 *
 * This is a reimplementation from the kernel function.
 */
static bool ktmm_cgroup_below_low(struct mem_cgroup *memcg)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return READ_ONCE(memcg->memory.elow) >=
		page_counter_read(&memcg->memory);
}


/**
 * ktmm_cgroup_below_min - if memory cgroup is below min memory thresh
 *
 * @memcg:	memory cgroup
 *
 * This is a reimplementation from the kernel function.
 */
static bool ktmm_cgroup_below_min(struct mem_cgroup *memcg)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	return READ_ONCE(memcg->memory.emin) >=
		page_counter_read(&memcg->memory);
}


/**
 * ktmm_update_lru_sizes - updates the size of the lru list
 *
 * @lruvec:		per memcg lruvec
 * @lru:		the lru list
 * @nr_zone_taken:	the number of folios taken from the lru list
 *
 * This is a reimplementation from the kernel function.
 */
static __always_inline void ktmm_update_lru_sizes(struct lruvec *lruvec,
			enum lru_list lru, unsigned long *nr_zone_taken)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		ktmm_cgroup_update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
	}

}


/**
 * ktmm_folio_evictable - if the folio is evictable or not
 *
 * @folio:	folio to test
 *
 * This is a reimplementation from the kernel function.
 */
static inline bool ktmm_folio_evictable(struct folio *folio)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	bool ret;

	rcu_read_lock();
	ret = !mapping_unevictable(folio_mapping(folio)) &&
		!folio_test_mlocked(folio);
	rcu_read_unlock();
	return ret;
}


/**
 * ktmm_folio_needs_release - if the folio needs release before free
 *
 * @folio:	folio to test
 *
 * This is a reimplementation from the kernel function.
 */
static inline bool ktmm_folio_needs_release(struct folio *folio)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	struct address_space *mapping = folio_mapping(folio);

	return folio_has_private(folio) || (mapping && mapping_release_always(mapping));
}


/**
 * scan_promote_list - scan promote lru folios for migration
 *
 * @nr_to_scan:		number to scan
 * @lruvec:		target lruvec
 * @sc:			scan control
 * @lru:		lru list to scan
 * @pgdat:		node data
 *
 * Scans the promote lru list for candidates to either migrate or bump down back
 * to the active lru list. This function should only really be utilized by the
 * pmem node.
 */
static void scan_promote_list(unsigned long nr_to_scan,
				struct lruvec *lruvec,
				struct scan_control *sc,
				enum lru_list lru,
				struct pglist_data *pgdat)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long nr_migrated = 0;
	isolate_mode_t isolate_mode = 0;
	LIST_HEAD(l_hold);
	int file = is_file_lru(lru);
	int nid = pgdat->node_id;

	struct list_head *src = &lruvec->lists[lru];

	if (list_empty(src))
		pr_debug("promote list empty");

	//pr_debug("scanning promote list");

	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
					&nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	pr_debug("pgdat %d scanned %lu on promote list", nid, nr_scanned);
	pr_debug("pgdat %d taken %lu on promote list", nid, nr_taken);

	/* ADDED: Track access patterns for each folio in promote list */
	if (!list_empty(&l_hold)) {
		struct folio *folio, *next;
		
		list_for_each_entry_safe(folio, next, &l_hold, lru) {
			/* Track access pattern for debugging/monitoring */
			track_folio_access(folio, pgdat, "PROMOTE_LIST");
		}
	}

	// if (nr_taken) {
	// 	unsigned int succeeded;
	// 	int ret = migrate_pages(&l_hold, alloc_normal_page,
	// 			NULL, 0, MIGRATE_SYNC, MR_MEMORY_HOTPLUG, &succeeded);
	// 	nr_migrated = (ret < 0 ? 0 : nr_taken - ret);
	// 	__mod_node_page_state(pgdat, NR_PROMOTED, nr_migrated);

	// 	pr_debug("pgdat %d migrated %lu folios from promote list", nid, nr_migrated);
	// }
  

  //dummy code
  if (nr_taken) {
    nr_migrated = 0;  // No migration actually happens
    pr_debug("pgdat %d MIGRATION DISABLED - would have migrated %lu folios from promote list", nid, nr_taken);
  }

	spin_lock_irq(&lruvec->lru_lock);

	ktmm_move_folios_to_lru(lruvec, &l_hold);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_hold);
	ktmm_free_unref_page_list(&l_hold);
}


/**
 * scan_active_list - scan lru folios from the active list
 *
 * @nr_to_scan:		number to scan
 * @lruvec:		target lruvec
 * @sc:			scan control
 * @lru:		lru list to scan
 * @pgdat:		node data
 *
 * This is a reimplementation of shrink_active_list from vmscan.c. Here, we scan
 * the active list and move folios either down to the inactive list or up to the
 * promote list. Folios will only be moved to the promote list if we are
 * scanning on the pmem node.
 */
static void scan_active_list(unsigned long nr_to_scan,
				struct lruvec *lruvec,
				struct scan_control *sc,
				enum lru_list lru,
				struct pglist_data *pgdat)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	LIST_HEAD(l_hold);	// The folios which were snipped off
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);
	LIST_HEAD(l_promote);
	unsigned nr_deactivate, nr_activate, nr_promote;
	unsigned nr_rotated = 0;
	int file = is_file_lru(lru);
	int nid = pgdat->node_id;
	
	//pr_info("scanning active list");

	// make sure pages in per-cpu lru list are added
	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	while (!list_empty(&l_hold)) {
		struct folio *folio;

		cond_resched();
		folio = lru_to_folio(&l_hold);
		list_del(&folio->lru);

		/* ADDED: Track page access pattern during active list scanning */
		track_folio_access(folio, pgdat, "ACTIVE_LIST");

		if (unlikely(!ktmm_folio_evictable(folio))) {
			ktmm_folio_putback_lru(folio);
			continue;
		}

		if (unlikely(buffer_heads_over_limit)) {
			if (ktmm_folio_needs_release(folio) &&
			    folio_trylock(folio)) {
				filemap_release_folio(folio, 0);
				folio_unlock(folio);
			}
		}

		// node migration
		if (pgdat->pm_node != 0) {
			//pr_debug("active pm_node");
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				pr_debug("set promote");
				//SetPagePromote(page); NEEDS TO BE MODULE TRACKED
				folio_set_promote(folio);
				list_add(&folio->lru, &l_promote);
				continue;
			}
		}

		// might not need, we only care about promoting here in the
		// module
		/*
		if (sc->only_promote) {
			list_add(&folio->lru, &l_active);
			continue;
		}
		*/

		// Referenced or rmap lock contention: rotate
		if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup,
				     &vm_flags) != 0) {
			/*
			  Identify referenced, file-backed active folios and
			  give them one more trip around the active list. So
			  that executable code get better chances to stay in
			  memory under moderate memory pressure.  Anon folios
			  are not likely to be evicted by use-once streaming
			  IO, plus JVM can create lots of anon VM_EXEC folios,
			  so we ignore them here.
			*/
			if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {
				nr_rotated += folio_nr_pages(folio);
				list_add(&folio->lru, &l_active);
				continue;
			}
		}

		folio_clear_active(folio);	// we are de-activating
		folio_set_workingset(folio);
		list_add(&folio->lru, &l_inactive);
	}

	// Move folios back to the lru list.
	spin_lock_irq(&lruvec->lru_lock);

	nr_activate = ktmm_move_folios_to_lru(lruvec, &l_active);
	nr_deactivate = ktmm_move_folios_to_lru(lruvec, &l_inactive);
	nr_promote = ktmm_move_folios_to_lru(lruvec, &l_promote);

	pr_debug("pgdat %d folio activated: %d", nid, nr_activate);
	pr_debug("pgdat %d folio deactivated: %d", nid, nr_deactivate);
	pr_debug("pgdat %d folio promoted: %d", nid, nr_promote);

	// Keep all free folios in l_active list
	list_splice(&l_inactive, &l_active);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_active);
	ktmm_free_unref_page_list(&l_active);
}


/**
 * scan_inactive_list - scan inactive lru list folios
 *
 * @nr_to_scan:		number to scan
 * @lruvec:		target lruvec
 * @sc:			scan control
 * @lru:		lru list to scan
 * @pgdat:		node data
 *
 * This is a reimplementation of shrink_inactive_list from vmscan.c. Here, we
 * scan folios and move them down to the pmem node if they have not been
 * referenced. If they are already on the pmem node, we only consider moving
 * them up the to active list if they have been referenced. We do not do any
 * reclaiming here, and let direct reclaim or kswapd take care of reclaiming
 * folios when neccessary.
 */
static unsigned long scan_inactive_list(unsigned long nr_to_scan,
					struct lruvec *lruvec,
					struct scan_control *sc,
					enum lru_list lru,
					struct pglist_data *pgdat)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	LIST_HEAD(folio_list);
	unsigned long nr_scanned;
	unsigned long nr_taken = 0;
	unsigned long nr_migrated = 0;
	bool file = is_file_lru(lru);
	int nid = pgdat->node_id;
	//pr_info("scanning inactive list");

	// make sure pages in per-cpu lru list are added
	ktmm_lru_add_drain();

	// We want to isolate the pages we are going to scan.
	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0) return 0;

	/* ADDED: Track access patterns for each folio in inactive list */
	if (!list_empty(&folio_list)) {
		struct folio *folio, *next;
		
		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			/* Track access pattern for debugging/monitoring */
			track_folio_access(folio, pgdat, "INACTIVE_LIST");
		}
	}

	//migrate pages down to the pmem node
	// if (pgdat->pm_node == 0 && pmem_node_id != -1) {
	// 	unsigned int succeeded;
	// 	int ret = migrate_pages(&folio_list, alloc_pmem_page, NULL, 
	// 				0, MIGRATE_SYNC, MR_MEMORY_HOTPLUG, &succeeded);
	// 	nr_migrated = (ret >= 0 ? nr_taken - ret : 0);
	// 	pr_debug("pgdat %d migrated %lu folios from inactive list", nid, nr_migrated);
	// 	__mod_node_page_state(pgdat, NR_DEMOTED, nr_migrated);
	// }
//dummy code
  if (pgdat->pm_node == 0 && pmem_node_id != -1) {
    nr_migrated = 0;  // No migration actually happens
    pr_debug("pgdat %d MIGRATION DISABLED - would have migrated %lu folios from inactive list", nid, nr_taken);
  }

	spin_lock_irq(&lruvec->lru_lock);

	ktmm_move_folios_to_lru(lruvec, &folio_list);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&folio_list);
	ktmm_free_unref_page_list(&folio_list);

	return nr_migrated;
}


/* SIMILAR TO: shrink_list() */
/**
 * scan_list - determines which scan function to call per list
 *
 * @lru:		lru list to scan
 * @nr_to_scan:		number to scan
 * @lruvec:		target lruvec
 * @sc:			scan control
 * @pgdat:		node data
 */
static unsigned long scan_list(enum lru_list lru, 
				unsigned long nr_to_scan,
				struct lruvec *lruvec, 
				struct scan_control *sc,
				struct pglist_data *pgdat)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	if (is_active_lru(lru))
		scan_active_list(nr_to_scan, lruvec, sc, lru, pgdat);

	if(is_promote_lru(lru))
		scan_promote_list(nr_to_scan, lruvec, sc, lru, pgdat);

	return scan_inactive_list(nr_to_scan, lruvec, sc, lru, pgdat);
}

/**
 * scan_all_dram_pages_comprehensive - Scan EVERY page in DRAM
 * 
 * @pgdat: node data struct
 * @sc: scan control
 *
 * This scans ALL pages including:
 * - LRU pages (active/inactive, anon/file)
 * - Unevictable pages 
 * - Mlocked pages
 * - Kernel pages
 * - Page cache pages
 * - Anonymous pages
 */
static unsigned long scan_all_dram_pages_comprehensive(struct pglist_data *pgdat, struct scan_control *sc)
{
    struct zone *zone;
    unsigned long total_scanned = 0;
    unsigned long total_accessed = 0;
    int nid = pgdat->node_id;
    
    printk(KERN_INFO "=== SCANNING 100%% OF DRAM PAGES ON NODE %d ===\n", nid);
    
    // Scan all zones in this node
    for (zone = pgdat->node_zones; zone; zone = ktmm_next_zone(zone)) {
        unsigned long zone_scanned = 0;
        unsigned long zone_accessed = 0;
        unsigned long pfn;
        
        if (!populated_zone(zone))
            continue;
            
        printk(KERN_INFO "Scanning zone %s: %lu free of %lu managed pages (range: %lu-%lu)\n", 
               zone->name, zone->free_area[0].nr_free, zone->managed_pages,
               zone->zone_start_pfn, zone->zone_start_pfn + zone->spanned_pages);
        
        // Method: Scan via pageblock iteration (most comprehensive)
        for (pfn = zone->zone_start_pfn; pfn < zone->zone_start_pfn + zone->spanned_pages; pfn++) {
            struct page *page;
            struct folio *folio;
            
            // Skip if not valid pfn
            if (!pfn_valid(pfn))
                continue;
                
            page = pfn_to_page(pfn);
            
            // Skip if page is not in this zone
            if (page_zone(page) != zone)
                continue;
                
            folio = page_folio(page);
            
            // Track this page's access
            if (track_folio_access(folio, pgdat, "DRAM_COMPREHENSIVE")) {
                zone_accessed++;
            }
            
            zone_scanned++;
            total_scanned++;
            
            // // Print progress every 10000 pages
            // if (total_scanned % 10000 == 0) {
            //     printk(KERN_INFO "Progress: scanned %lu total pages, %lu accessed\n", 
            //            total_scanned, total_accessed);
            // }
            
            // Avoid soft lockup - reschedule every 1000 pages
            if (total_scanned % 1000 == 0) {
                cond_resched();
            }
        }
        
        total_accessed += zone_accessed;
        
        printk(KERN_INFO "Zone %s: scanned %lu pages, %lu accessed pages\n",
               zone->name, zone_scanned, zone_accessed);
    }
    
    printk(KERN_INFO "=== NODE %d COMPLETE: scanned %lu TOTAL pages, %lu ACCESSED pages ===\n",
           nid, total_scanned, total_accessed);
    
    return total_scanned;
}

/**
 * force_scan_all_memory - Force scanning of ALL memory regions
 * 
 * @pgdat: node data struct
 */
static void force_scan_all_memory(struct pglist_data *pgdat)
{
    struct zone *zone;
    int nid = pgdat->node_id;
    
    printk(KERN_INFO "=== PREPARING TO SCAN 100%% OF DRAM ON NODE %d ===\n", nid);
    
    // Print memory statistics
    for (zone = pgdat->node_zones; zone; zone = ktmm_next_zone(zone)) {
        if (!populated_zone(zone))
            continue;
            
        printk(KERN_INFO "Zone %s: start_pfn=%lu, spanned=%lu, present=%lu, managed=%lu\n",
               zone->name, zone->zone_start_pfn, zone->spanned_pages,
               zone->present_pages, zone->managed_pages);
    }
    
    // Force all types of pages to be accessible
    ktmm_lru_add_drain();
    
    printk(KERN_INFO "Ready to scan ALL DRAM pages on node %d\n", nid);
}

/**
 * scan_node_comprehensive - Scan 100% of DRAM pages
 * 
 * @pgdat: node data struct
 * @sc: scan control
 * @reclaim: memory reclaim cookie
 */
static void scan_node_comprehensive(pg_data_t *pgdat, 
                                   struct scan_control *sc,
                                   struct mem_cgroup_reclaim_cookie *reclaim)
{
    int nid = pgdat->node_id;
    ktime_t start_time, end_time;
    s64 scan_duration_ns;
    const char *node_type = (pgdat->pm_node == 0) ? "DRAM" : "PMEM";
    
    /* Only scan DRAM nodes comprehensively */
    if (pgdat->pm_node != 0) {
        printk(KERN_INFO "Skipping comprehensive scan on PMEM node %d\n", nid);
        return;
    }
    
    /* Reset printk overhead counter */
    g_printk_overhead_ns = 0;
    
    /* Prepare for scanning */
    force_scan_all_memory(pgdat);
    
    /* Start timing */
    start_time = ktime_get();
    
    /* Perform 100% comprehensive scan of ALL DRAM pages */
    unsigned long total_pages_scanned = scan_all_dram_pages_comprehensive(pgdat, sc);
    
    /* End timing */
    end_time = ktime_get();
    scan_duration_ns = ktime_to_ns(ktime_sub(end_time, start_time));
    
    /* Calculate pure scan time (excluding printk overhead) */
    s64 pure_scan_time_ns = scan_duration_ns - g_printk_overhead_ns;
    
    /* Print final results */
    printk(KERN_INFO "=== NODE %d (%s): SCANNED 100%% OF DRAM - %lu PAGES IN %lld MICROSECONDS ===\n",
           nid, node_type, total_pages_scanned, pure_scan_time_ns / 1000);
}

/**
 * scan_node - scan a node's LRU lists
 * 
 * @pgdat:	node data struct
 * @nid:	node ID number
 * @reclaim:	memory reclaim cookie
 *
 * This is responsible for scanning the lruvec per memory cgroup.
 */
static void scan_node(pg_data_t *pgdat, 
		struct scan_control *sc,
		struct mem_cgroup_reclaim_cookie *reclaim)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	enum lru_list lru;
	struct mem_cgroup *memcg;
	int nid = pgdat->node_id;
	int memcg_count;

  ktime_t start_time, end_time;
	s64 scan_duration_ns;
	s64 pure_scan_time_ns;
  const char *node_type = (pgdat->pm_node == 0) ? "DRAM" : "PMEM";

	/* Reset printk overhead counter before scan */
	g_printk_overhead_ns = 0;

  /* Start timing - capture time before any scanning operations */
	start_time = ktime_get();

	memset(&sc->nr, 0, sizeof(sc->nr));
	memcg = ktmm_mem_cgroup_iter(NULL, NULL, reclaim);
	sc->target_mem_cgroup = memcg;

	//pr_info("scanning lists on node %d", nid);
	memcg_count = 0;
	do {
		struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;
		unsigned long reclaimed;
		unsigned long scanned;

		memcg_count += 1;

		if (ktmm_cgroup_below_min(memcg)) {
			/*
			 * Hard protection.
			 * If there is no reclaimable memory, OOM.
			 */
			continue;
		} else if (ktmm_cgroup_below_low(memcg)) {
			/*
			 * Soft protection.
			 * Respect the protection only as long as
			 * there is an unprotected supply of 
			 * reclaimable memory from other cgroups.
			 */
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
			// memcg_memory_event(memcg, MEMCG_LOW);
		}

		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;

		for_each_evictable_lru(lru) {
			unsigned long nr_to_scan = ULONG_MAX;  // Scan ALL pages

			scan_list(lru, nr_to_scan, lruvec, sc, pgdat);
		}
	} while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
	
  /* End timing - capture time after all scanning is complete */
	end_time = ktime_get();
	scan_duration_ns = ktime_to_ns(ktime_sub(end_time, start_time));
	
	/* Calculate pure scan time (excluding printk overhead) */
	pure_scan_time_ns = scan_duration_ns - g_printk_overhead_ns;

	/* Print clean output */
	printk(KERN_INFO "Scan time: Node %d (%s) = %lld microseconds (printk overhead: %lld us)\n",
	       nid, node_type, pure_scan_time_ns / 1000, g_printk_overhead_ns / 1000);
}


/*****************************************************************************
 * Daemon Functions & Related
 *****************************************************************************/

/**
 * tmemd_try_to_sleep - put tmemd to sleep for a short time
 *
 * @pgdat:	node data
 * @nid:	node id
 *
 * @returns:	none
 *
 */
static void tmemd_try_to_sleep(pg_data_t *pgdat, int nid)
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	long remaining = 0;
	DEFINE_WAIT(wait);

	//pr_info("tmemd trying to sleep: %d", nid);

	if (freezing(current) || kthread_should_stop())
		return;
	
	prepare_to_wait(&tmemd_wait[nid], &wait, TASK_INTERRUPTIBLE);
	remaining = schedule_timeout(5 * HZ);  //sudarshan changed to 5 seconds for better page access detection

	finish_wait(&tmemd_wait[nid], &wait);
}


/**
 * tmemd - page promotion daemon
 *
 * @p:	pointer to node data struct (pglist_data)
 *
 * This is stored in a local array for module access only.
 */
static int tmemd(void *p) 
{
  //printk(KERN_INFO "sudarshan: entered %s\n", __func__);

	pg_data_t *pgdat = (pg_data_t *)p;
	int nid = pgdat->node_id;
	struct task_struct *task = current;
	const struct cpumask *cpumask = cpumask_of_node(nid);

	struct mem_cgroup_reclaim_cookie reclaim = {
		.pgdat = pgdat,
	};

	struct reclaim_state reclaim_state = {
		.reclaimed_slab = 0,
	};

	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		//.gfp_mask = TMEMD_GFP_FLAGS,
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode, //do not delay writing to disk
		.may_unmap = 1,
		.may_swap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.only_promote = 1,
	};

	// Only allow node's CPUs to run this task
	if(!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(task, cpumask);

	current->reclaim_state = &reclaim_state;

	/*
	 * Tell MM that we are a memory allocator, and that we are actually
	 * kswapd. We are also set to suspend as needed.
	 *
	 * Flags are located in include/sched.h for more info.
	 */
	task->flags |= PF_MEMALLOC | PF_KSWAPD;


	//pr_info("tmemd started on node %d", nid);

	/*
	 * Loop every few seconds and scan the node's LRU lists.
	 * If the thread is signaled to stop, we will exit.
	 */
	for ( ; ; )
	{
		// Scan 100% of DRAM pages (only for DRAM nodes)
		if (pgdat->pm_node == 0) {
			scan_node_comprehensive(pgdat, &sc, &reclaim);
		} else {
			// Use original scanner for PMEM
			scan_node(pgdat, &sc, &reclaim);
		}
		
		if (kthread_should_stop()) break;

		tmemd_try_to_sleep(pgdat, nid);
	}

	task->flags &= ~(PF_MEMALLOC | PF_KSWAPD);
	current->reclaim_state = NULL;
	
	return 0;
}


/*****************************************************************************
 * Start & Stop
 *****************************************************************************/

/****************** ADD VMSCAN HOOKS HERE ************************/
static struct ktmm_hook vmscan_hooks[] = {
	HOOK("mem_cgroup_iter", ktmm_mem_cgroup_iter, &pt_mem_cgroup_iter),
	HOOK("zone_watermark_ok", ktmm_zone_watermark_ok_safe, &pt_zone_watermark_ok_safe),
	HOOK("first_online_pgdat", ktmm_first_online_pgdat, &pt_first_online_pgdat),
	HOOK("next_zone", ktmm_next_zone, &pt_next_zone),
	HOOK("free_unref_page_list", ktmm_free_unref_page_list, &pt_free_unref_page_list),
	HOOK("lru_add_drain", ktmm_lru_add_drain, &pt_lru_add_drain),
	HOOK("mem_cgroup_update_lru_size", ktmm_cgroup_update_lru_size, &pt_cgroup_update_lru_size),
	HOOK("__mem_cgroup_uncharge_list", ktmm_cgroup_uncharge_list, &pt_cgroup_uncharge_list),
	HOOK("isolate_lru_folios", ktmm_isolate_lru_folios, &pt_isolate_lru_folios),
	HOOK("move_folios_to_lru", ktmm_move_folios_to_lru, &pt_move_folios_to_lru),
	HOOK("folio_putback_lru", ktmm_folio_putback_lru, &pt_folio_putback_lru),
	HOOK("folio_referenced", ktmm_folio_referenced, &pt_folio_referenced),
	HOOK("node_page_state", ktmm_node_page_state, &pt_node_page_state),
	HOOK("__alloc_pages", ktmm_alloc_pages, &pt_alloc_pages),
};


/**
 * Daemons are only started on online/active nodes. They are
 * currently stored in a local array.
 *
 * We will also need to define the behavior for hot-plugging nodes
 * into the system, as this code only sets up daemons on nodes 
 * that are online the moment the module starts.
 *
 */
int tmemd_start_available(void) 
{
  
	int i;
	int nid;
	int ret;

	set_ktmm_scan();

	/* initialize wait queues for sleeping */
	for (i = 0; i < MAX_NUMNODES; i++)
		init_waitqueue_head(&tmemd_wait[i]);

	ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
	
	for_each_online_node(nid)
	{
		pg_data_t *pgdat = NODE_DATA(nid);

		/* !! EMULATE PMEM NODE !! */
		if (nid == 1) {
			pr_info("Emulating pmem node");
			set_pmem_node_id(nid);
			set_pmem_node(nid);
		}

        	tmemd_list[nid] = kthread_run(&tmemd, pgdat, "tmemd");
	}

	return ret;
}


/**
 * This stops all thread daemons for each node when exiting.
 * It uses the node ID to grab the daemon out of our local list.
 */
void tmemd_stop_all(void)
{
	int nid;

	for_each_online_node(nid)
	{
		kthread_stop(tmemd_list[nid]);
	}

	uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
}