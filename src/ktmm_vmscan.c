/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 *
 *  Migration logic adapted from uts_migrate.c (kernel 5.14) for kernel 6.1
 *  CRITICAL: Does NOT call folio_put() on already-isolated folios!
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

/* Migration debug counters */
static atomic64_t migrate_filter_anon = ATOMIC64_INIT(0);
static atomic64_t migrate_filter_compound = ATOMIC64_INIT(0);
static atomic64_t migrate_filter_no_mapping = ATOMIC64_INIT(0);
static atomic64_t migrate_attempted = ATOMIC64_INIT(0);
static atomic64_t migrate_success = ATOMIC64_INIT(0);

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

	/* Migration debug counters */
	u64 filter_anon = atomic64_read(&migrate_filter_anon);
	u64 filter_compound = atomic64_read(&migrate_filter_compound);
	u64 filter_no_mapping = atomic64_read(&migrate_filter_no_mapping);
	u64 mig_attempted = atomic64_read(&migrate_attempted);
	u64 mig_success = atomic64_read(&migrate_success);

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

	/* Print migration debug info */
	printk(KERN_INFO "*** KTMM MIGRATION DEBUG ***\n");
	printk(KERN_INFO "  Filtered: anon=%llu, compound=%llu, no_mapping=%llu\n",
	       filter_anon, filter_compound, filter_no_mapping);
	printk(KERN_INFO "  Migrate: attempted=%llu, success=%llu\n",
	       mig_attempted, mig_success);
	printk(KERN_INFO "*** END DEBUG ***\n");

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
	return pt_zone_watermark_ok_safe(z, order, mark, highest_zoneidx);
}


static struct pglist_data *ktmm_first_online_pgdat(void)
{
	return pt_first_online_pgdat();
}


static struct zone *ktmm_next_zone(struct zone *zone)
{
	return pt_next_zone(zone);
}


static void ktmm_free_unref_page_list(struct list_head *list)
{
	return pt_free_unref_page_list(list);
}


static void ktmm_lru_add_drain(void)
{
	pt_lru_add_drain();
}


static void ktmm_cgroup_update_lru_size(struct lruvec *lruvec, enum lru_list lru,
					int zid, int nr_pages)
{
	pt_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
}


static void ktmm_cgroup_uncharge_list(struct list_head *page_list)
{
	pt_cgroup_uncharge_list(page_list);
}


static unsigned long ktmm_isolate_lru_folios(unsigned long nr_to_scan, struct lruvec *lruvec,
					struct list_head *dst, unsigned long *nr_scanned,
					struct scan_control *sc, enum lru_list lru)
{
	return pt_isolate_lru_folios(nr_to_scan, lruvec, dst, nr_scanned, sc, lru);
}


static unsigned int ktmm_move_folios_to_lru(struct lruvec *lruvec, struct list_head *list)
{
	return pt_move_folios_to_lru(lruvec, list);
}


static void ktmm_folio_putback_lru(struct folio *folio)
{
	pt_folio_putback_lru(folio);
}


static int ktmm_folio_referenced(struct folio *folio, int is_locked,
				struct mem_cgroup *memcg, unsigned long *vm_flags)
{
	return pt_folio_referenced(folio, is_locked, memcg, vm_flags);
}


/*****************************************************************************
 * Page Access Tracking Helper Functions
 *****************************************************************************/

/**
 * track_folio_access - track if folio was previously accessed
 */
static int track_folio_access(struct folio *folio, struct pglist_data *pgdat, const char *location)
{
    int was_accessed;
    
    /* Check the referenced flag */
    was_accessed = folio_test_referenced(folio);
    
    if (was_accessed) {
        /* Immediately clear the bit after checking */
        folio_clear_referenced(folio);
    }
    
    return was_accessed;
}


/*****************************************************************************
 * MIGRATION FUNCTIONS - Adapted from uts_migrate.c for kernel 6.1
 *
 * CRITICAL DIFFERENCES FROM uts_migrate.c:
 * 1. uts_migrate.c calls isolate_lru_page() itself and expects caller to hold extra ref
 * 2. KTMM uses ktmm_isolate_lru_folios() which already isolates folios
 * 3. Therefore we do NOT call folio_put() - folios only have isolation ref
 * 4. Kernel 6.1 migrate_pages() has 7 args (includes ret_succeeded)
 *****************************************************************************/

/**
 * ktmm_alloc_migration_page - allocate page on target node for migration
 * @page: source page (used for order, etc.)
 * @private: target NUMA node ID
 *
 * EXACT same logic as uts_alloc_migrate_page() from uts_migrate.c
 */
static struct page *ktmm_alloc_migration_page(struct page *page, unsigned long private)
{
	int nid = (int)private;
	struct page *newpage;

	/* Allocate destination page on the target node */
	newpage = alloc_pages_node(nid, GFP_HIGHUSER_MOVABLE | __GFP_THISNODE, 0);

	return newpage;
}

/**
 * ktmm_free_migration_page - free page on migration failure
 * @page: page to free
 * @private: unused
 *
 * EXACT same logic as uts_free_migrate_page() from uts_migrate.c
 */
static void ktmm_free_migration_page(struct page *page, unsigned long private)
{
	__free_pages(page, 0);
}

/**
 * ktmm_migrate_folio_list - migrate a list of already-isolated folios
 * @folio_list: list of folios (already isolated by ktmm_isolate_lru_folios)
 * @target_nid: destination NUMA node
 * @nr_succeeded_out: output - number of successfully migrated pages
 *
 * This is the KTMM adaptation of uts_migrate.c logic for kernel 6.1.
 *
 * CRITICAL: Unlike uts_migrate.c, we do NOT call folio_put() because:
 * - uts_migrate.c expects caller to hold an extra ref, then calls isolate_lru_page()
 * - KTMM folios are already isolated by ktmm_isolate_lru_folios() with just isolation ref
 * - Calling folio_put() would drop the isolation ref and CRASH!
 *
 * Returns: number of pages that failed to migrate (0 = all succeeded)
 */
static int ktmm_migrate_folio_list(struct list_head *folio_list, int target_nid,
				   unsigned long *nr_succeeded_out)
{
	LIST_HEAD(migrate_list);
	struct folio *folio, *next;
	unsigned int nr_succeeded = 0;
	int nr_to_migrate = 0;
	int ret;

	if (list_empty(folio_list)) {
		if (nr_succeeded_out)
			*nr_succeeded_out = 0;
		return 0;
	}

	/*
	 * Filter folios and build migration list.
	 * Same filters as uts_migrate.c: skip anon, compound, no-mapping pages.
	 *
	 * IMPORTANT: We move suitable folios to migrate_list.
	 * Unsuitable folios stay in folio_list for caller to handle.
	 */
	list_for_each_entry_safe(folio, next, folio_list, lru) {
		/* Same quick filters as uts_migrate.c */
		if (folio_test_anon(folio)) {
			atomic64_inc(&migrate_filter_anon);
			continue;  /* Leave in folio_list */
		}

		if (folio_test_large(folio)) {
			atomic64_inc(&migrate_filter_compound);
			continue;  /* Leave in folio_list */
		}

		if (!folio_mapping(folio)) {
			atomic64_inc(&migrate_filter_no_mapping);
			continue;  /* Leave in folio_list */
		}

		/*
		 * Folio passes filters. Move to migration list.
		 *
		 * CRITICAL: Do NOT call folio_put() here!
		 * The folio only has the isolation ref from ktmm_isolate_lru_folios().
		 * uts_migrate.c calls put_page() because caller provided extra ref.
		 * We don't have that extra ref, so we must not drop it!
		 */
		list_del(&folio->lru);
		list_add_tail(&folio->lru, &migrate_list);
		nr_to_migrate++;
	}

	if (nr_to_migrate == 0) {
		if (nr_succeeded_out)
			*nr_succeeded_out = 0;
		return 0;
	}

	atomic64_add(nr_to_migrate, &migrate_attempted);

	/*
	 * Call migrate_pages() - kernel 6.1 signature with 7 args.
	 *
	 * From uts_migrate.c (kernel 5.14):
	 *   ret = migrate_pages(&plist, uts_alloc_migrate_page,
	 *                       uts_free_migrate_page, target_nid,
	 *                       MIGRATE_SYNC, MR_NUMA_MISPLACED);
	 *
	 * Kernel 6.1 adds: unsigned int *ret_succeeded
	 */
	ret = migrate_pages(&migrate_list,
			    ktmm_alloc_migration_page,
			    ktmm_free_migration_page,
			    (unsigned long)target_nid,
			    MIGRATE_SYNC,
			    MR_NUMA_MISPLACED,
			    &nr_succeeded);

	atomic64_add(nr_succeeded, &migrate_success);

	/*
	 * Any folios left in migrate_list failed migration.
	 * Put them back on LRU (same as uts_migrate.c using putback_lru_page).
	 */
	if (!list_empty(&migrate_list)) {
		struct folio *f, *f_next;

		list_for_each_entry_safe(f, f_next, &migrate_list, lru) {
			list_del_init(&f->lru);
			ktmm_folio_putback_lru(f);
		}
	}

	if (nr_succeeded_out)
		*nr_succeeded_out = nr_succeeded;

	return ret;
}


/*****************************************************************************
 * ALLOC & SWAP (Legacy functions - kept for compatibility)
 *****************************************************************************/

/**
 * alloc_pmem_page - allocate a page on pmem node
 */
struct page* alloc_pmem_page(struct page *page, unsigned long data)
{
	gfp_t gfp_mask = GFP_USER | __GFP_PMEM;
	return alloc_page(gfp_mask);
}


/**
 * alloc_normal_page - allocate a page on a normal node
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
 */
static bool ktmm_cgroup_below_low(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memory.elow) >=
		page_counter_read(&memcg->memory);
}


/**
 * ktmm_cgroup_below_min - if memory cgroup is below min memory thresh
 */
static bool ktmm_cgroup_below_min(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memory.emin) >=
		page_counter_read(&memcg->memory);
}


/**
 * ktmm_update_lru_sizes - updates the size of the lru list
 */
static __always_inline void ktmm_update_lru_sizes(struct lruvec *lruvec,
			enum lru_list lru, unsigned long *nr_zone_taken)
{
	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++) {
		if (!nr_zone_taken[zid])
			continue;

		ktmm_cgroup_update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
	}
}


/**
 * ktmm_folio_evictable - if the folio is evictable or not
 */
static inline bool ktmm_folio_evictable(struct folio *folio)
{
	bool ret;

	rcu_read_lock();
	ret = !mapping_unevictable(folio_mapping(folio)) &&
		!folio_test_mlocked(folio);
	rcu_read_unlock();
	return ret;
}


/**
 * ktmm_folio_needs_release - if the folio needs release before free
 */
static inline bool ktmm_folio_needs_release(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);

	return folio_has_private(folio) || (mapping && mapping_release_always(mapping));
}


/*****************************************************************************
 * LIST SCANNING FUNCTIONS
 *****************************************************************************/

/**
 * scan_promote_list - scan promote lru folios for migration to DRAM
 *
 * Uses ktmm_migrate_folio_list() which adapts uts_migrate.c logic.
 */
static void scan_promote_list(unsigned long nr_to_scan,
				struct lruvec *lruvec,
				struct scan_control *sc,
				enum lru_list lru,
				struct pglist_data *pgdat)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long nr_migrated = 0;
	__maybe_unused isolate_mode_t isolate_mode = 0;
	LIST_HEAD(l_hold);
	int file = is_file_lru(lru);
	__maybe_unused int nid = pgdat->node_id;
	int target_node = 0;  /* DRAM node */

	struct list_head *src = &lruvec->lists[lru];

	if (list_empty(src))
		return;

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

	if (nr_taken == 0)
		goto done;

	/*
	 * PROMOTION: PMEM -> DRAM migration.
	 *
	 * ktmm_migrate_folio_list() will:
	 * 1. Filter unsuitable folios (leave them in l_hold)
	 * 2. Move suitable folios to internal migrate_list
	 * 3. Call migrate_pages() once
	 * 4. Put back failures via ktmm_folio_putback_lru()
	 * 5. Return successes in nr_migrated
	 *
	 * Folios that didn't pass filter remain in l_hold and will be
	 * put back by ktmm_move_folios_to_lru() below.
	 */
	ktmm_migrate_folio_list(&l_hold, target_node, &nr_migrated);

	if (nr_migrated > 0) {
		__mod_node_page_state(pgdat, NR_PROMOTED, nr_migrated);
		atomic64_add(nr_migrated, &total_pages_promoted);
		atomic64_add(nr_migrated, &pages_promote_to_dram);
		printk(KERN_INFO "KTMM: Promoted %lu pages from PMEM to DRAM\n", nr_migrated);
	}

done:
	/*
	 * Put remaining folios back to LRU.
	 * These are folios that didn't pass the migration filter.
	 */
	spin_lock_irq(&lruvec->lru_lock);

	ktmm_move_folios_to_lru(lruvec, &l_hold);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_hold);
	ktmm_free_unref_page_list(&l_hold);
}


/**
 * scan_active_list - scan lru folios from the active list
 */
static void scan_active_list(unsigned long nr_to_scan,
				struct lruvec *lruvec,
				struct scan_control *sc,
				enum lru_list lru,
				struct pglist_data *pgdat)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long vm_flags;
	LIST_HEAD(l_hold);
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);
	LIST_HEAD(l_promote);
	__maybe_unused unsigned nr_deactivate, nr_activate, nr_promote;
	__maybe_unused unsigned nr_rotated = 0;
	int file = is_file_lru(lru);
	__maybe_unused int nid = pgdat->node_id;

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

		/* Track page access pattern */
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

		/* PMEM node: check for promotion candidates */
		if (pgdat->pm_node != 0) {
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				folio_set_promote(folio);
				list_add(&folio->lru, &l_promote);
				atomic64_inc(&pages_active_to_promote);
				continue;
			}
		}

		/* Referenced or rmap lock contention: rotate */
		if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup,
				     &vm_flags) != 0) {
			if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {
				nr_rotated += folio_nr_pages(folio);
				list_add(&folio->lru, &l_active);
				continue;
			}
		}

		folio_clear_active(folio);
		folio_set_workingset(folio);
		list_add(&folio->lru, &l_inactive);
		atomic64_inc(&pages_active_to_inactive);
	}

	spin_lock_irq(&lruvec->lru_lock);

	nr_activate = ktmm_move_folios_to_lru(lruvec, &l_active);
	nr_deactivate = ktmm_move_folios_to_lru(lruvec, &l_inactive);
	nr_promote = ktmm_move_folios_to_lru(lruvec, &l_promote);

	list_splice(&l_inactive, &l_active);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_active);
	ktmm_free_unref_page_list(&l_active);
}


/**
 * scan_inactive_list - scan inactive lru list folios
 *
 * Uses ktmm_migrate_folio_list() for DRAM->PMEM demotion.
 */
static unsigned long scan_inactive_list(unsigned long nr_to_scan,
					struct lruvec *lruvec,
					struct scan_control *sc,
					enum lru_list lru,
					struct pglist_data *pgdat)
{
	LIST_HEAD(folio_list);
	LIST_HEAD(l_active);
	unsigned long nr_scanned;
	unsigned long nr_taken = 0;
	unsigned long nr_migrated = 0;
	unsigned long nr_activate = 0;
	unsigned long vm_flags;
	bool file = is_file_lru(lru);
	__maybe_unused int nid = pgdat->node_id;

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0)
		return 0;

	/* Track pages scanned from inactive list */
	atomic64_add(nr_taken, &pages_scanned_inactive);

	/*
	 * PMEM NODE: Check if inactive pages are referenced and activate them.
	 * Flow: inactive -> active -> promote -> DRAM
	 */
	if (pgdat->pm_node != 0) {
		struct folio *folio, *next;
		
		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				list_del(&folio->lru);
				folio_set_active(folio);
				list_add(&folio->lru, &l_active);
				nr_activate++;
				atomic64_inc(&pages_inactive_to_active);
			}
		}
	}

	/*
	 * DRAM NODE: Migrate cold (unreferenced) pages to PMEM.
	 * Uses ktmm_migrate_folio_list() with uts_migrate.c logic.
	 */
	if (pgdat->pm_node == 0 && pmem_node_id != -1) {
		int target_node = pmem_node_id;

		ktmm_migrate_folio_list(&folio_list, target_node, &nr_migrated);

		if (nr_migrated > 0) {
			__mod_node_page_state(pgdat, NR_DEMOTED, nr_migrated);
			atomic64_add(nr_migrated, &total_pages_demoted);
			printk(KERN_INFO "KTMM: Demoted %lu pages from DRAM to PMEM\n", nr_migrated);
		}
	}
  
	spin_lock_irq(&lruvec->lru_lock);

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


/**
 * scan_list - determines which scan function to call per list
 */
static unsigned long scan_list(enum lru_list lru, 
				unsigned long nr_to_scan,
				struct lruvec *lruvec, 
				struct scan_control *sc,
				struct pglist_data *pgdat)
{
	if (is_active_lru(lru))
		scan_active_list(nr_to_scan, lruvec, sc, lru, pgdat);

	if(is_promote_lru(lru))
		scan_promote_list(nr_to_scan, lruvec, sc, lru, pgdat);

	return scan_inactive_list(nr_to_scan, lruvec, sc, lru, pgdat);
}


/**
 * scan_node - scan a node's LRU lists
 */
static void scan_node(pg_data_t *pgdat, 
		struct scan_control *sc,
		struct mem_cgroup_reclaim_cookie *reclaim)
{
	enum lru_list lru;
	struct mem_cgroup *memcg;
	int nid = pgdat->node_id;
	__maybe_unused int memcg_count;

	memset(&sc->nr, 0, sizeof(sc->nr));
	memcg = ktmm_mem_cgroup_iter(NULL, NULL, reclaim);
	sc->target_mem_cgroup = memcg;

	memcg_count = 0;
	do {
		struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;

		memcg_count += 1;

		if (ktmm_cgroup_below_min(memcg)) {
			continue;
		} else if (ktmm_cgroup_below_low(memcg)) {
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
		}

		for_each_evictable_lru(lru) {
			unsigned long nr_to_scan = 1024;

			scan_list(lru, nr_to_scan, lruvec, sc, pgdat);
		}
	} while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
}


/*****************************************************************************
 * Daemon Functions & Related
 *****************************************************************************/

static void tmemd_try_to_sleep(pg_data_t *pgdat, int nid)
{
	long remaining = 0;
	DEFINE_WAIT(wait);

	if (freezing(current) || kthread_should_stop())
		return;
	
	prepare_to_wait(&tmemd_wait[nid], &wait, TASK_INTERRUPTIBLE);
	remaining = schedule_timeout(5 * HZ);

	finish_wait(&tmemd_wait[nid], &wait);
}


static int tmemd(void *p) 
{
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
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.only_promote = 1,
	};

	if(!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(task, cpumask);

	current->reclaim_state = &reclaim_state;

	task->flags |= PF_MEMALLOC | PF_KSWAPD;

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


int tmemd_start_available(void) 
{
	int i;
	int nid;
	int ret;

	set_ktmm_scan();

	for (i = 0; i < MAX_NUMNODES; i++)
		init_waitqueue_head(&tmemd_wait[i]);

	ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));

	timer_setup(&page_stats_timer, page_stats_timer_callback, 0);
	mod_timer(&page_stats_timer, jiffies + 5 * HZ);
	
	for_each_online_node(nid)
	{
		pg_data_t *pgdat = NODE_DATA(nid);

		if (nid == 1) {
			pr_info("Emulating pmem node");
			set_pmem_node_id(nid);
			set_pmem_node(nid);
		}

        	tmemd_list[nid] = kthread_run(&tmemd, pgdat, "tmemd");
	}

	return ret;
}


void tmemd_stop_all(void)
{
	int nid;

	del_timer_sync(&page_stats_timer);

	printk(KERN_INFO "*** KTMM FINAL STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
	       (u64)atomic64_read(&total_pages_promoted),
	       (u64)atomic64_read(&total_pages_demoted));

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
	
	printk(KERN_INFO "*** KTMM FINAL MIGRATION STATS ***\n");
	printk(KERN_INFO "  Filtered: anon=%llu, compound=%llu, no_mapping=%llu\n",
	       (u64)atomic64_read(&migrate_filter_anon),
	       (u64)atomic64_read(&migrate_filter_compound),
	       (u64)atomic64_read(&migrate_filter_no_mapping));
	printk(KERN_INFO "  Migrate: attempted=%llu, success=%llu\n",
	       (u64)atomic64_read(&migrate_attempted),
	       (u64)atomic64_read(&migrate_success));
	printk(KERN_INFO "*** END FINAL STATS ***\n");

	for_each_online_node(nid)
	{
		kthread_stop(tmemd_list[nid]);
	}

	uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
}