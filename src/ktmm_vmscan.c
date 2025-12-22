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
#include <linux/timer.h>
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


/*****************************************************************************
 * Promotion/Demotion Page Counters
 *****************************************************************************/

/* Atomic counters for tracking total promoted and demoted pages */
static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);

/*****************************************************************************
 * Page Flow Debug Counters
 * Track page movement: inactive -> active -> promote -> DRAM
 *****************************************************************************/

/* Counters for page flow between lists */
static atomic64_t pages_inactive_to_active = ATOMIC64_INIT(0);   /* inactive -> active (activation) */
static atomic64_t pages_active_to_inactive = ATOMIC64_INIT(0);   /* active -> inactive (deactivation) */
static atomic64_t pages_active_to_promote = ATOMIC64_INIT(0);    /* active -> promote list */
static atomic64_t pages_promote_to_dram = ATOMIC64_INIT(0);      /* promote -> DRAM (successful migration) */
static atomic64_t pages_promote_failed = ATOMIC64_INIT(0);       /* promote migration failures */

/* Counters for pages scanned/taken from each list per cycle */
static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);

/* Timer for periodic printing of counters */
static struct timer_list page_stats_timer;

/**
 * page_stats_timer_callback - timer callback that prints promotion/demotion stats
 * @t: timer_list pointer
 *
 * This function is called every 5 seconds to print the total number of
 * pages promoted and demoted.
 */
static void page_stats_timer_callback(struct timer_list *t)
{
	u64 promoted = atomic64_read(&total_pages_promoted);
	u64 demoted = atomic64_read(&total_pages_demoted);

	/* Page flow counters */
	u64 inactive_to_active = atomic64_read(&pages_inactive_to_active);
	u64 active_to_inactive = atomic64_read(&pages_active_to_inactive);
	u64 active_to_promote = atomic64_read(&pages_active_to_promote);
	u64 promote_to_dram = atomic64_read(&pages_promote_to_dram);
	u64 promote_failed = atomic64_read(&pages_promote_failed);
	u64 scanned_inactive = atomic64_read(&pages_scanned_inactive);
	u64 scanned_active = atomic64_read(&pages_scanned_active);
	u64 scanned_promote = atomic64_read(&pages_scanned_promote);

	printk(KERN_INFO "*** KTMM PAGE STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
	       promoted, demoted);

	/* Print page flow debug info */
	printk(KERN_INFO "*** KTMM PAGE FLOW DEBUG ***\n");
	printk(KERN_INFO "  Scanned: inactive=%llu, active=%llu, promote=%llu\n",
	       scanned_inactive, scanned_active, scanned_promote);
	printk(KERN_INFO "  Flow: inactive->active=%llu, active->inactive=%llu\n",
	       inactive_to_active, active_to_inactive);
	printk(KERN_INFO "  Flow: active->promote=%llu, promote->DRAM=%llu (failed=%llu)\n",
	       active_to_promote, promote_to_dram, promote_failed);
	printk(KERN_INFO "*** END PAGE FLOW DEBUG ***\n");

	/* Re-arm the timer for another 5 seconds */
	mod_timer(&page_stats_timer, jiffies + 5 * HZ);
}


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


/*****************************************************************************
 * Page Access Tracking Helper Functions
 *****************************************************************************/

/**
 * track_folio_access - track if folio was previously accessed
 * 
 * @folio: folio to check
 * @pgdat: node data to determine node type
 * @location: descriptive string for logging context
 * 
 * Returns: 1 if page was previously accessed, 0 if first access
 * 
 * This function checks the referenced bit and if it's set (accessed),
 * it prints the access information and immediately clears the bit.
 * This way, if the same folio is checked again in the same scan cycle,
 * it won't show as accessed again (avoiding duplicate logging).
 */
static int track_folio_access(struct folio *folio, struct pglist_data *pgdat, const char *location)
{
    int was_accessed;
    const char *node_type = (pgdat->pm_node == 0) ? "DRAM" : "PMEM";
    
    /* Check the referenced flag */
    was_accessed = folio_test_referenced(folio);
    
    if (was_accessed) {
        /* Print the access information */
        // printk(KERN_INFO "*** ACCESSED at %s: referenced_bit=1 (folio=%p, node=%s, jiffies=%lu) ***\n", 
        //          location, folio, node_type, jiffies);
        
        /* Immediately clear the bit after printing so we don't print it again in the same scan */
        folio_clear_referenced(folio);  /* DISABLED: Not clearing reference bit */
    } 
    //else {
    //     printk(KERN_INFO "Not accessed at %s: referenced_bit=0 (folio=%p, node=%s, jiffies=%lu)\n", 
    //              location, folio, node_type, jiffies);
    // }
    
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
 * ktmm_migrate_folio_manual - manually migrate a single folio to target node
 * Following the exact pattern from migration.c for kernel 5.3
 * 
 * @folio: folio to migrate
 * @target_node: destination NUMA node
 * @pgdat: page data structure
 *
 * Returns: 0 on success, negative error code on failure
 */
static int ktmm_migrate_folio_manual(struct folio *folio, int target_node, struct pglist_data *pgdat)
{
	struct page *page = &folio->page;
	struct page *newpage = NULL;
	struct address_space *mapping;
	int rc = -EINVAL;
	
	// Get the mapping (similar to migration.c line 93)
	mapping = folio_mapping(folio);
	if (!mapping) {
		// No mapping, can't migrate
		return -EINVAL;
	}
	
	// Check if page is suitable for migration (basic checks from migration.c)
	if (folio_test_unevictable(folio)) {
		return -EINVAL;
	}
	
	// Allocate new page on target node (migration.c line 146)
	newpage = alloc_pages_node(target_node, GFP_HIGHUSER_MOVABLE, 0);
	if (!newpage) {
		return -ENOMEM;
	}
	
	// Try migration via mapping->a_ops->migratepage if available (migration.c line 153)
	if (mapping->a_ops && mapping->a_ops->migrate_folio) {
		rc = mapping->a_ops->migrate_folio(mapping, page_folio(newpage), folio, MIGRATE_SYNC);
		
		if (rc == MIGRATEPAGE_SUCCESS) {
			// Success! Don't free newpage, ownership transferred
			return 0;
		} else {
			// Failed, free newpage and return error
			__free_pages(newpage, 0);
			return rc;
		}
	}
	
	// If no migrate_folio operation, free newpage and fail
	__free_pages(newpage, 0);
	return -ENOSYS;
}

/**
 * ktmm_alloc_migration_target - allocate page on target node for migration
 * @page: page being migrated (not used)
 * @private: pointer to target node ID
 *
 * Returns newly allocated page on target node
 */

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
		// pr_debug("promote list empty");

	//pr_debug("scanning promote list");

	if (!sc->may_unmap)
		isolate_mode |= ISOLATE_UNMAPPED;

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
					&nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	/* Track pages scanned from promote list */
	atomic64_add(nr_taken, &pages_scanned_promote);

	// pr_debug("pgdat %d scanned %lu on promote list", nid, nr_scanned);
	// pr_debug("pgdat %d taken %lu on promote list", nid, nr_taken);

	/* ADDED: Track access patterns for each folio in promote list */
	// DISABLED: Too much console output
	// if (!list_empty(&l_hold)) {
	// 	struct folio *folio, *next;
	// 	
	// 	list_for_each_entry_safe(folio, next, &l_hold, lru) {
	// 		/* Track access pattern for debugging/monitoring */
	// 		track_folio_access(folio, pgdat, "PROMOTE_LIST");
	// 	}
	// }

	// Manual migration folio by folio
	// Migrate page-by-page from PMEM to DRAM
	if (nr_taken > 0) {
		struct folio *folio, *next;
		int target_node = 0;  // DRAM node
		int migrated_count = 0;
		
		list_for_each_entry_safe(folio, next, &l_hold, lru) {
			int rc = ktmm_migrate_folio_manual(folio, target_node, pgdat);
			if (rc == 0) {
				migrated_count++;
				/* Track successful promote -> DRAM migration */
				atomic64_inc(&pages_promote_to_dram);
				// Remove from list since migration succeeded
        printk(KERN_INFO "Sudarshan total migrated: %d\n", migrated_count);


				list_del(&folio->lru);
			} else {
				/* Track failed promote migration */
				atomic64_inc(&pages_promote_failed);
			}
			// If migration fails, leave it in list to be put back
		}
		
		nr_migrated = migrated_count;
		if (nr_migrated > 0) {
			__mod_node_page_state(pgdat, NR_PROMOTED, nr_migrated);
			/* Update the total promoted counter */
			atomic64_add(nr_migrated, &total_pages_promoted);
			// printk("pgdat %d PROMOTED %lu folios from PMEM to DRAM", nid, nr_migrated);
		}
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

	/* Track pages scanned from active list */
	atomic64_add(nr_taken, &pages_scanned_active);

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
				// pr_debug("set promote");
				//SetPagePromote(page); NEEDS TO BE MODULE TRACKED
				folio_set_promote(folio);
				list_add(&folio->lru, &l_promote);
				/* Track active -> promote movement */
				atomic64_inc(&pages_active_to_promote);
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
		/* Track active -> inactive movement (deactivation) */
		atomic64_inc(&pages_active_to_inactive);
	}

	// Move folios back to the lru list.
	spin_lock_irq(&lruvec->lru_lock);

	nr_activate = ktmm_move_folios_to_lru(lruvec, &l_active);
	nr_deactivate = ktmm_move_folios_to_lru(lruvec, &l_inactive);
	nr_promote = ktmm_move_folios_to_lru(lruvec, &l_promote);

	// pr_debug("pgdat %d folio activated: %d", nid, nr_activate);
	// pr_debug("pgdat %d folio deactivated: %d", nid, nr_deactivate);
	// pr_debug("pgdat %d folio promoted: %d", nid, nr_promote);

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
	LIST_HEAD(l_active);	/* folios to activate (for PMEM node) */
	unsigned long nr_scanned;
	unsigned long nr_taken = 0;
	unsigned long nr_migrated = 0;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_activate = 0;
	unsigned long vm_flags;
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

	/* Track pages scanned from inactive list */
	atomic64_add(nr_taken, &pages_scanned_inactive);

	/* ADDED: Track access patterns for each folio in inactive list */
	// DISABLED: Too much console output
	// if (!list_empty(&folio_list)) {
	// 	struct folio *folio, *next;
	// 	
	// 	list_for_each_entry_safe(folio, next, &folio_list, lru) {
	// 		/* Track access pattern for debugging/monitoring */
	// 		track_folio_access(folio, pgdat, "INACTIVE_LIST");
	// 	}
	// }

	/*
	 * PMEM NODE: Check if inactive pages are referenced and activate them.
	 * This is the key step to move pages from inactive -> active list,
	 * so they can eventually be promoted to DRAM.
	 * Flow: inactive -> active -> promote -> DRAM
	 */
	if (pgdat->pm_node != 0) {
		struct folio *folio, *next;
		
		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			/* Check if the folio was referenced (accessed) */
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				/* Referenced! Move to active list */
				list_del(&folio->lru);
				folio_set_active(folio);
				list_add(&folio->lru, &l_active);
				nr_activate++;
				/* Track inactive -> active movement */
				atomic64_inc(&pages_inactive_to_active);
			}
			/* Unreferenced pages stay in folio_list and go back to inactive */
		}
	}

	//migrate pages down to the pmem node
	// Manual migration following migration.c pattern
	// Migrate page-by-page from DRAM to PMEM
	if (pgdat->pm_node == 0 && pmem_node_id != -1) {
		struct folio *folio, *next;
		int target_node = pmem_node_id;  // PMEM node
		int migrated_count = 0;
		
		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			int rc = ktmm_migrate_folio_manual(folio, target_node, pgdat);
			if (rc == 0) {
				migrated_count++;
				// Remove from list since migration succeeded
				list_del(&folio->lru);
			}
			// If migration fails, leave it in list to be put back
		}
		
		nr_migrated = migrated_count;
		if (nr_migrated > 0) {
			__mod_node_page_state(pgdat, NR_DEMOTED, nr_migrated);
			/* Update the total demoted counter */
			atomic64_add(nr_migrated, &total_pages_demoted);
			// printk("pgdat %d DEMOTED %lu folios from DRAM to PMEM", nid, nr_migrated);
		}
	}
  
	spin_lock_irq(&lruvec->lru_lock);

	/* Move activated folios to active LRU list (PMEM node only) */
	if (nr_activate > 0) {
		ktmm_move_folios_to_lru(lruvec, &l_active);
	}

	ktmm_move_folios_to_lru(lruvec, &folio_list);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_active);
	ktmm_free_unref_page_list(&l_active);
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
	
	/* Timing and page count tracking */
	u64 scan_start_time, scan_end_time;
	u64 total_scan_time_us;
	unsigned long total_pages_scanned = 0;

	scan_start_time = ktime_get_ns();

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
			unsigned long nr_to_scan = 1024;  //3000000//sudarshan changed this to 256 for better page access detection

			scan_list(lru, nr_to_scan, lruvec, sc, pgdat);
			
			/* Track total pages scanned across all LRU lists */
			total_pages_scanned += nr_to_scan;
		}

		/*
		 * PMEM NODE: Explicitly scan the promote lists.
		 * for_each_evictable_lru only covers the 4 standard LRU lists,
		 * NOT the promote lists. So we must scan them explicitly here
		 * to drain pages from promote list -> DRAM.
		 */
		if (pgdat->pm_node != 0) {
			unsigned long nr_to_scan = 1024;
			
			/* Scan promote list for anonymous pages */
			scan_promote_list(nr_to_scan, lruvec, sc, LRU_PROMOTE_ANON, pgdat);
			
			/* Scan promote list for file-backed pages */
			scan_promote_list(nr_to_scan, lruvec, sc, LRU_PROMOTE_FILE, pgdat);
		}
	} while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
	
	/* Calculate and print scan statistics */
	scan_end_time = ktime_get_ns();
	total_scan_time_us = (scan_end_time - scan_start_time) / 1000;  /* Convert nanoseconds to microseconds */
	
	// printk(KERN_INFO "*** SCAN_STATS (Node %d): Total Pages Scanned: %lu, Total Scan Time: %llu us ***\n", 
	//        nid, total_pages_scanned, total_scan_time_us);
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
		scan_node(pgdat, &sc, &reclaim);

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

	/* Initialize and start the page stats timer */
	timer_setup(&page_stats_timer, page_stats_timer_callback, 0);
	mod_timer(&page_stats_timer, jiffies + 5 * HZ);
	
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

	/* Stop and delete the page stats timer */
	del_timer_sync(&page_stats_timer);

	/* Print final stats before stopping */
	printk(KERN_INFO "*** KTMM FINAL STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
	       (u64)atomic64_read(&total_pages_promoted),
	       (u64)atomic64_read(&total_pages_demoted));

	/* Print final page flow stats */
	printk(KERN_INFO "*** KTMM FINAL PAGE FLOW STATS ***\n");
	printk(KERN_INFO "  Total Scanned: inactive=%llu, active=%llu, promote=%llu\n",
	       (u64)atomic64_read(&pages_scanned_inactive),
	       (u64)atomic64_read(&pages_scanned_active),
	       (u64)atomic64_read(&pages_scanned_promote));
	printk(KERN_INFO "  Total Flow: inactive->active=%llu, active->inactive=%llu\n",
	       (u64)atomic64_read(&pages_inactive_to_active),
	       (u64)atomic64_read(&pages_active_to_inactive));
	printk(KERN_INFO "  Total Flow: active->promote=%llu, promote->DRAM=%llu (failed=%llu)\n",
	       (u64)atomic64_read(&pages_active_to_promote),
	       (u64)atomic64_read(&pages_promote_to_dram),
	       (u64)atomic64_read(&pages_promote_failed));
	printk(KERN_INFO "*** END FINAL PAGE FLOW STATS ***\n");

	for_each_online_node(nid)
	{
		kthread_stop(tmemd_list[nid]);
	}

	uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
}