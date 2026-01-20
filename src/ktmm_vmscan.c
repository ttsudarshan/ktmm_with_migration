/*
 * ktmm_vmscan.c
 *
 * Page scanning and related functions.
 * Updated for Linux Kernel 6.1
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
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/memcontrol.h>
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
 * Promotion/Demotion Balance & Stats
 *****************************************************************************/

/* Atomic counters for tracking total promoted and demoted pages */
static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);

/* * Balance Counter for 1:1 Ratio Enforcement
 * Positive = More Promoted. Negative = More Demoted.
 * Goal is to keep this near 0.
 */
static atomic64_t migration_balance = ATOMIC64_INIT(0);
#define BALANCE_THRESHOLD 512  /* Allow small burst variance, but throttle if gap > 512 pages */

/* Counters for page flow between lists */
static atomic64_t pages_inactive_to_active = ATOMIC64_INIT(0);   
static atomic64_t pages_active_to_inactive = ATOMIC64_INIT(0);   
static atomic64_t pages_active_to_promote = ATOMIC64_INIT(0);    
static atomic64_t pages_promote_to_dram = ATOMIC64_INIT(0);      
static atomic64_t pages_promote_failed = ATOMIC64_INIT(0);       

/* Counters for pages scanned/taken from each list per cycle */
static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);

/* Timer for periodic printing of counters */
static struct timer_list page_stats_timer;

static void page_stats_timer_callback(struct timer_list *t)
{
	u64 promoted = atomic64_read(&total_pages_promoted);
	u64 demoted = atomic64_read(&total_pages_demoted);
	s64 balance = atomic64_read(&migration_balance);

	u64 inactive_to_active = atomic64_read(&pages_inactive_to_active);
	u64 active_to_inactive = atomic64_read(&pages_active_to_inactive);
	u64 active_to_promote = atomic64_read(&pages_active_to_promote);
	u64 promote_to_dram = atomic64_read(&pages_promote_to_dram);
	u64 promote_failed = atomic64_read(&pages_promote_failed);
	u64 scanned_inactive = atomic64_read(&pages_scanned_inactive);
	u64 scanned_active = atomic64_read(&pages_scanned_active);
	u64 scanned_promote = atomic64_read(&pages_scanned_promote);

	printk(KERN_INFO "*** KTMM PAGE STATS: Total Promoted: %llu, Total Demoted: %llu (Balance: %lld) ***\n",
	       promoted, demoted, balance);

	printk(KERN_INFO "*** KTMM PAGE FLOW DEBUG ***\n");
	printk(KERN_INFO "  Scanned: inactive=%llu, active=%llu, promote=%llu\n",
	       scanned_inactive, scanned_active, scanned_promote);
	printk(KERN_INFO "  Flow: inactive->active=%llu, active->inactive=%llu\n",
	       inactive_to_active, active_to_inactive);
	printk(KERN_INFO "  Flow: active->promote=%llu, promote->DRAM=%llu (failed=%llu)\n",
	       active_to_promote, promote_to_dram, promote_failed);
	printk(KERN_INFO "*** END PAGE FLOW DEBUG ***\n");

	mod_timer(&page_stats_timer, jiffies + 5 * HZ);
}

/************** MISC HOOKED FUNCTION PROTOTYPES *****************************/
/* Standard hooks as provided in previous file */
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
static struct page *(*pt_alloc_pages)(gfp_t gfp_mask, unsigned int order, int preferred_nid,
					nodemask_t *nodemask);

/**************** KTMM IMPLEMENTATION OF HOOKED FUNCTION **********************/
/* Wrappers to call original functions */
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
 * ALLOC & MIGRATION HELPERS
 *****************************************************************************/

/*
 * ktmm_new_page_node - Callback for migrate_pages
 * Allocates a new page on the specified node.
 * * FIX: Must use struct page* signature to match new_page_t in migrate.h
 */
static struct page *ktmm_new_page_node(struct page *src, unsigned long private)
{
	int nid = (int)private;
	gfp_t gfp_mask = GFP_HIGHUSER_MOVABLE | __GFP_THISNODE;
	struct page *newpage;

	newpage = alloc_pages_node(nid, gfp_mask, 0);
	return newpage;
}

static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
					nodemask_t *nodemask)
{
	/* Passthrough for now to avoid complexity */
	return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);
}

/*****************************************************************************
 * Node Scanning, Shrinking, and Promotion
 *****************************************************************************/

static bool ktmm_cgroup_below_low(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memory.elow) >= page_counter_read(&memcg->memory);
}

static bool ktmm_cgroup_below_min(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memory.emin) >= page_counter_read(&memcg->memory);
}

static inline bool ktmm_folio_evictable(struct folio *folio)
{
	bool ret;
	rcu_read_lock();
	ret = !mapping_unevictable(folio_mapping(folio)) && !folio_test_mlocked(folio);
	rcu_read_unlock();
	return ret;
}

static inline bool ktmm_folio_needs_release(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);
	return folio_has_private(folio) || (mapping && mapping_release_always(mapping));
}

/**
 * scan_promote_list - scan promote lru folios for migration (PMEM -> DRAM)
 */
static void scan_promote_list(unsigned long nr_to_scan,
				struct lruvec *lruvec,
				struct scan_control *sc,
				enum lru_list lru,
				struct pglist_data *pgdat)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	unsigned long nr_succeeded = 0;
	LIST_HEAD(l_hold);      /* Isolated pages */
	LIST_HEAD(l_migrate);   /* Pages selected for migration */
	int file = is_file_lru(lru);
	// int nid = pgdat->node_id;

	/* 1:1 Ratio Check: If we have promoted way more than demoted, pause promotion */
	if (atomic64_read(&migration_balance) > BALANCE_THRESHOLD) {
		/* We are too far ahead in promotions, skip this cycle to let demotion catch up */
		return;
	}

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);
	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
					&nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	atomic64_add(nr_taken, &pages_scanned_promote);

	if (nr_taken == 0)
		return;

	/* Identify candidates for migration to DRAM (Node 0) */
	if (!list_empty(&l_hold)) {
		struct folio *folio, *next;
		
		list_for_each_entry_safe(folio, next, &l_hold, lru) {
			list_del(&folio->lru);
			list_add(&folio->lru, &l_migrate);
		}
	}

	/* Perform Batch Migration using standard migrate_pages */
	if (!list_empty(&l_migrate)) {
		int target_nid = 0; /* Target DRAM */
		int ret;

		/* * MIGRATE_SYNC_LIGHT: Async but waits for some locks. 
		 * Reduces freezing compared to SYNC.
		 * * FIX: Using ktmm_new_page_node to match signature.
		 */
		ret = migrate_pages(&l_migrate, ktmm_new_page_node, NULL, 
				    (unsigned long)target_nid, MIGRATE_SYNC_LIGHT, 
				    MR_NUMA_MISPLACED, (unsigned int *)&nr_succeeded);

		if (nr_succeeded > 0) {
			__mod_node_page_state(pgdat, NR_PROMOTED, nr_succeeded);
			atomic64_add(nr_succeeded, &total_pages_promoted);
			atomic64_add(nr_succeeded, &pages_promote_to_dram);
			/* Adjust balance: Promotion increases positive balance */
			atomic64_add(nr_succeeded, &migration_balance);
		}
		
		/* Count failures */
		if (!list_empty(&l_migrate)) {
			/* Anything left in l_migrate failed to migrate */
			unsigned long failed = 0;
			struct folio *f;
			list_for_each_entry(f, &l_migrate, lru) failed++;
			atomic64_add(failed, &pages_promote_failed);
			
			/* Move failed back to hold list for putback */
			list_splice_init(&l_migrate, &l_hold);
		}
	}

	/* Put back any pages that failed to migrate */
	spin_lock_irq(&lruvec->lru_lock);
	ktmm_move_folios_to_lru(lruvec, &l_hold);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_hold);
	ktmm_free_unref_page_list(&l_hold);
}


/**
 * scan_active_list - scan lru folios from the active list
 * Moves pages Active -> Inactive OR Active -> Promote (if referenced on PMEM)
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
	unsigned nr_deactivate, nr_activate, nr_promote;
	unsigned nr_rotated = 0;
	int file = is_file_lru(lru);
	// int nid = pgdat->node_id;

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);
	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	atomic64_add(nr_taken, &pages_scanned_active);

	while (!list_empty(&l_hold)) {
		struct folio *folio;

		cond_resched();
		folio = lru_to_folio(&l_hold);
		list_del(&folio->lru);

		if (unlikely(!ktmm_folio_evictable(folio))) {
			ktmm_folio_putback_lru(folio);
			continue;
		}

		// node migration check for PMEM node
		if (pgdat->pm_node != 0) {
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				// Referenced on PMEM? Move to Promote list
				folio_set_promote(folio);
				list_add(&folio->lru, &l_promote);
				atomic64_inc(&pages_active_to_promote);
				continue;
			}
		}

		// Referenced? Rotate in Active list
		if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags) != 0) {
			if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {
				nr_rotated += folio_nr_pages(folio);
				list_add(&folio->lru, &l_active);
				continue;
			}
		}

		// Not referenced? Deactivate to Inactive list
		folio_clear_active(folio);
		folio_set_workingset(folio);
		list_add(&folio->lru, &l_inactive);
		atomic64_inc(&pages_active_to_inactive);
	}

	spin_lock_irq(&lruvec->lru_lock);
	nr_activate = ktmm_move_folios_to_lru(lruvec, &l_active);
	nr_deactivate = ktmm_move_folios_to_lru(lruvec, &l_inactive);
	nr_promote = ktmm_move_folios_to_lru(lruvec, &l_promote);
	
	list_splice(&l_inactive, &l_active); // Cleanup remainder
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_active);
	ktmm_free_unref_page_list(&l_active);
}


/**
 * scan_inactive_list - scan inactive lru list folios
 * Handles Demotion (DRAM -> PMEM) and Activation (PMEM -> Active)
 */
static unsigned long scan_inactive_list(unsigned long nr_to_scan,
					struct lruvec *lruvec,
					struct scan_control *sc,
					enum lru_list lru,
					struct pglist_data *pgdat)
{
	LIST_HEAD(folio_list);
	LIST_HEAD(l_active);	/* folios to activate */
	LIST_HEAD(l_migrate);   /* folios to demote */
	unsigned long nr_scanned;
	unsigned long nr_taken = 0;
	unsigned long nr_succeeded = 0;
	unsigned long nr_activate = 0;
	unsigned long vm_flags;
	bool file = is_file_lru(lru);
	// int nid = pgdat->node_id;

	/* 1:1 Ratio Check for Demotion */
	bool allow_demotion = true;
	if (atomic64_read(&migration_balance) < -BALANCE_THRESHOLD) {
		/* We have demoted way more than promoted, pause demotion */
		allow_demotion = false;
	}

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);
	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0) return 0;

	atomic64_add(nr_taken, &pages_scanned_inactive);

	/* * Logic separation:
	 * If on PMEM Node: Check references to Activate (Promote path start)
	 * If on DRAM Node: Check if we should Demote (DRAM -> PMEM)
	 */
	
	if (pgdat->pm_node != 0) {
		/* PMEM NODE: Check for Activation */
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
	} else if (pgdat->pm_node == 0 && pmem_node_id != -1 && allow_demotion) {
		/* DRAM NODE: Demote cold pages to PMEM */
		struct folio *folio, *next;
		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			/* If NOT referenced recently, queue for demotion */
			if (!ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				list_del(&folio->lru);
				list_add(&folio->lru, &l_migrate);
			}
		}
	}

	/* Perform Demotion Migration */
	if (!list_empty(&l_migrate)) {
		int target_nid = pmem_node_id;
		int ret;

		/* FIX: Using ktmm_new_page_node to match signature */
		ret = migrate_pages(&l_migrate, ktmm_new_page_node, NULL,
				    (unsigned long)target_nid, MIGRATE_SYNC_LIGHT,
				    MR_NUMA_MISPLACED, (unsigned int *)&nr_succeeded);

		if (nr_succeeded > 0) {
			__mod_node_page_state(pgdat, NR_DEMOTED, nr_succeeded);
			atomic64_add(nr_succeeded, &total_pages_demoted);
			/* Adjust balance: Demotion decreases balance (more negative) */
			atomic64_sub(nr_succeeded, &migration_balance);
		}

		/* Put back failed migrations */
		list_splice_init(&l_migrate, &folio_list);
	}
  
	spin_lock_irq(&lruvec->lru_lock);

	if (nr_activate > 0)
		ktmm_move_folios_to_lru(lruvec, &l_active);

	/* Put back remaining pages (failed migrations or unreferenced PMEM pages) */
	ktmm_move_folios_to_lru(lruvec, &folio_list);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_active);
	ktmm_free_unref_page_list(&l_active);
	ktmm_cgroup_uncharge_list(&folio_list);
	ktmm_free_unref_page_list(&folio_list);

	return nr_succeeded;
}


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


static void scan_node(pg_data_t *pgdat, 
		struct scan_control *sc,
		struct mem_cgroup_reclaim_cookie *reclaim)
{
	enum lru_list lru;
	struct mem_cgroup *memcg;
	int nid = pgdat->node_id;
	
	memset(&sc->nr, 0, sizeof(sc->nr));
	memcg = ktmm_mem_cgroup_iter(NULL, NULL, reclaim);
	sc->target_mem_cgroup = memcg;

	do {
		struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;

		if (ktmm_cgroup_below_min(memcg)) {
			continue;
		} else if (ktmm_cgroup_below_low(memcg)) {
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
		}

		for_each_evictable_lru(lru) {
			unsigned long nr_to_scan = 256; 
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
	/* Sleep for 5 seconds */
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

	/* Updated scan_control for 6.1 */
	struct scan_control sc = {
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		//.gfp_mask = TMEMD_GFP_FLAGS, // gfp_mask removed from scan_control in recent kernels or moved
		.priority = DEF_PRIORITY,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
		// .only_promote removed in newer kernels, handled by custom logic
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

	for_each_online_node(nid)
	{
		if (tmemd_list[nid])
			kthread_stop(tmemd_list[nid]);
	}

	uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
}