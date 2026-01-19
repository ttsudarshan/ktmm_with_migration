/* =========================
 * ktmm_vmscan.c (Fixed for Kernel 6.1 + Linker Bypass)
 * ========================= */

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

/* Bulk Migration Definitions */
#define BATCH_N 32
static atomic64_t mig_attempted = ATOMIC64_INIT(0);
static atomic64_t mig_succeeded = ATOMIC64_INIT(0);

/* * DYNAMIC LOOKUP FOR BULK API 
 * We use a function pointer to avoid linker errors if the symbol 
 * isn't explicitly exported by the kernel.
 */
typedef int (*uts_migrate_vec_t)(struct page **pages, int nr_pages, int target_nid);
static uts_migrate_vec_t pt_uts_migrate_file_pages_bulk_vec = NULL;

/************** PAGE ACCESS TRACKING HASHTABLE ******************************/
/* Hashtable to track first access time of pages */
#define PAGE_ACCESS_HASH_BITS 16  /* 2^16 = 65536 buckets */
static DEFINE_HASHTABLE(page_access_hash, PAGE_ACCESS_HASH_BITS);
static DEFINE_SPINLOCK(page_access_lock);  /* Spinlock for hashtable access */

/* Structure to store page access information in hashtable */
struct page_access_entry {
	struct hlist_node hash_node;    /* Hash list node */
	unsigned long pfn;               /* Page frame number as key */
	unsigned long first_access_jiffies;  /* Jiffies when first accessed */
};

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

static int track_folio_access(struct folio *folio, struct pglist_data *pgdat, const char *location)
{
    int was_accessed;
    const char *node_type = (pgdat->pm_node == 0) ? "DRAM" : "PMEM";
    unsigned long pfn;
    struct page_access_entry *entry;
    unsigned long first_access_jiffies = 0;
    unsigned long current_jiffies;
    bool found = false;
    
    /* Check the referenced flag */
    was_accessed = folio_test_referenced(folio);
    
    if (was_accessed) {
        current_jiffies = jiffies;
        pfn = folio_pfn(folio);
        
        spin_lock(&page_access_lock);
        hash_for_each_possible(page_access_hash, entry, hash_node, pfn) {
            if (entry->pfn == pfn) {
                first_access_jiffies = entry->first_access_jiffies;
                found = true;
                break;
            }
        }
        
        if (!found) {
            entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
            if (entry) {
                entry->pfn = pfn;
                entry->first_access_jiffies = current_jiffies;
                hash_add(page_access_hash, &entry->hash_node, pfn);
                first_access_jiffies = current_jiffies;
            } else {
                printk(KERN_WARNING "Failed to allocate memory for page access entry\n");
            }
        }
        spin_unlock(&page_access_lock);
        
        /* FIXED: Added 'access_age=%lu' to the format string to match the arguments */
        printk(KERN_INFO "*** ACCESSED at %s: referenced_bit=1 (folio=%p, node=%s, current_jiffies=%lu, first_access_jiffies=%lu, access_age=%lu) ***\n",
                 location, folio, node_type, current_jiffies, first_access_jiffies, 
                 (current_jiffies - first_access_jiffies));
        
        folio_clear_referenced(folio);
    } 
    
    return was_accessed;
}

/*****************************************************************************
 * ALLOC & SWAP
 *****************************************************************************/

struct page* alloc_pmem_page(struct  page *page, unsigned long data)
{
	gfp_t gfp_mask = GFP_USER | __GFP_PMEM;
	return alloc_page(gfp_mask);
}

struct page* alloc_normal_page(struct page *page, unsigned long data)
{
        gfp_t gfp_mask = GFP_USER;
        return alloc_page(gfp_mask);
}

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
 * Bulk Migration Helper (Resolved Dynamically)
 *****************************************************************************/

/**
 * migrate_folios_bulk - Migrate a list of folios using the bulk vector API
 */
static unsigned long migrate_folios_bulk(struct list_head *folio_list, int target_nid)
{
	struct page *vec[BATCH_N];
	int n = 0, i;
	unsigned long nr_migrated = 0;
	struct folio *folio, *next;

	if (list_empty(folio_list))
		return 0;

	/* If we failed to resolve the function, abort */
	if (!pt_uts_migrate_file_pages_bulk_vec) {
		/* Warn once to avoid log spam */
		static bool warned = false;
		if (!warned) {
			pr_err("KTMM: uts_migrate_file_pages_bulk_vec symbol missing. Migration disabled.\n");
			warned = true;
		}
		return 0;
	}

	/* Iterate through the list of isolated folios */
	list_for_each_entry_safe(folio, next, folio_list, lru) {
		struct page *page = folio_page(folio, 0);

		/* Add to batch */
		vec[n++] = page;
		
		/* Remove from the hold list so we can process the batch */
		list_del_init(&folio->lru);

		/* If batch is full, execute migration */
		if (n == BATCH_N) {
			int ret;
			
			atomic64_add(n, &mig_attempted);
			
			ret = pt_uts_migrate_file_pages_bulk_vec(vec, n, target_nid);

			/* * If migration failed for specific pages (vec[i] != NULL),
			 * put them back on LRU.
			 */
			for (i = 0; i < n; i++) {
				if (vec[i]) {
					ktmm_folio_putback_lru(page_folio(vec[i]));
				}
			}

			if (ret >= 0) {
				unsigned long success_count = (unsigned long)(n - ret);
				atomic64_add(success_count, &mig_succeeded);
				nr_migrated += success_count;
			}
			
			n = 0; /* Reset batch */
		}
	}

	/* Process remaining items in the batch */
	if (n > 0) {
		int ret;
		atomic64_add(n, &mig_attempted);
		
		ret = pt_uts_migrate_file_pages_bulk_vec(vec, n, target_nid);

		for (i = 0; i < n; i++) {
			if (vec[i]) {
				ktmm_folio_putback_lru(page_folio(vec[i]));
			}
		}

		if (ret >= 0) {
			unsigned long success_count = (unsigned long)(n - ret);
			atomic64_add(success_count, &mig_succeeded);
			nr_migrated += success_count;
		}
	}

	return nr_migrated;
}

/*****************************************************************************
 * Node Scanning, Shrinking, and Promotion
 *****************************************************************************/

static bool ktmm_cgroup_below_low(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memory.elow) >=
		page_counter_read(&memcg->memory);
}

static bool ktmm_cgroup_below_min(struct mem_cgroup *memcg)
{
	return READ_ONCE(memcg->memory.emin) >=
		page_counter_read(&memcg->memory);
}

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

static inline bool ktmm_folio_evictable(struct folio *folio)
{
	bool ret;

	rcu_read_lock();
	ret = !mapping_unevictable(folio_mapping(folio)) &&
		!folio_test_mlocked(folio);
	rcu_read_unlock();
	return ret;
}

static inline bool ktmm_folio_needs_release(struct folio *folio)
{
	struct address_space *mapping = folio_mapping(folio);
	return folio_has_private(folio) || (mapping && mapping_release_always(mapping));
}

/**
 * scan_promote_list - scan promote lru folios for migration
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
	isolate_mode_t isolate_mode = 0;
	LIST_HEAD(l_hold);
	int file = is_file_lru(lru);
	//int nid = pgdat->node_id;

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

	/* Track access patterns */
	if (!list_empty(&l_hold)) {
		struct folio *folio, *next;
		list_for_each_entry_safe(folio, next, &l_hold, lru) {
			track_folio_access(folio, pgdat, "PROMOTE_LIST");
		}
	}

	/* * BULK MIGRATION IMPLEMENTATION (Promote PMEM -> DRAM) */
	if (nr_taken) {
		int target_node = 0; /* Hardcoded to DRAM for promotion */
		
		nr_migrated = migrate_folios_bulk(&l_hold, target_node);
		
		__mod_node_page_state(pgdat, NR_PROMOTED, nr_migrated);
	}

	/* Cleanup */
	if (!list_empty(&l_hold)) {
		spin_lock_irq(&lruvec->lru_lock);
		ktmm_move_folios_to_lru(lruvec, &l_hold);
		__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
		spin_unlock_irq(&lruvec->lru_lock);
		
		ktmm_cgroup_uncharge_list(&l_hold);
		ktmm_free_unref_page_list(&l_hold);
	} else {
		__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	}
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
	unsigned nr_deactivate, nr_activate, nr_promote;
	unsigned nr_rotated = 0;
	int file = is_file_lru(lru);
	
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
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				folio_set_promote(folio);
				list_add(&folio->lru, &l_promote);
				continue;
			}
		}

		// Referenced or rmap lock contention: rotate
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
	}

	// Move folios back to the lru list.
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
 */
static unsigned long scan_inactive_list(unsigned long nr_to_scan,
					struct lruvec *lruvec,
					struct scan_control *sc,
					enum lru_list lru,
					struct pglist_data *pgdat)
{
	LIST_HEAD(folio_list);
	unsigned long nr_scanned;
	unsigned long nr_taken = 0;
	unsigned long nr_migrated = 0;
	bool file = is_file_lru(lru);
	//int nid = pgdat->node_id;

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);
	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0) return 0;

	if (!list_empty(&folio_list)) {
		struct folio *folio, *next;
		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			track_folio_access(folio, pgdat, "INACTIVE_LIST");
		}
	}

	/* * BULK MIGRATION IMPLEMENTATION (Demote DRAM -> PMEM) */
	if (pgdat->pm_node == 0 && pmem_node_id != -1) {
		nr_migrated = migrate_folios_bulk(&folio_list, pmem_node_id);
		__mod_node_page_state(pgdat, NR_DEMOTED, nr_migrated);
	}

	/* Cleanup remaining folios */
	if (!list_empty(&folio_list)) {
		spin_lock_irq(&lruvec->lru_lock);
		ktmm_move_folios_to_lru(lruvec, &folio_list);
		__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
		spin_unlock_irq(&lruvec->lru_lock);

		ktmm_cgroup_uncharge_list(&folio_list);
		ktmm_free_unref_page_list(&folio_list);
	} else {
		__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
	}

	return nr_migrated;
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
	
	/* Timing and page count tracking */
	u64 scan_start_time, scan_end_time;
	u64 total_scan_time_us;
	unsigned long total_pages_scanned = 0;

	scan_start_time = ktime_get_ns();

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
			unsigned long nr_to_scan = 3000000; 

			scan_list(lru, nr_to_scan, lruvec, sc, pgdat);
			
			total_pages_scanned += nr_to_scan;
		}
	} while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
	
	scan_end_time = ktime_get_ns();
	total_scan_time_us = (scan_end_time - scan_start_time) / 1000;
	
	printk(KERN_INFO "*** SCAN_STATS (Node %d): Total Pages Scanned: %lu, Total Scan Time: %llu us ***\n", 
	       nid, total_pages_scanned, total_scan_time_us);
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

/* Helper to lookup symbols even if they are not exported (Bypassing modpost checks) */
static unsigned long lookup_external_symbol(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	unsigned long addr;

	if (register_kprobe(&kp) < 0)
		return 0;
	
	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	return addr;
}

int tmemd_start_available(void) 
{
	int i;
	int nid;
	int ret;

	set_ktmm_scan();
	
	hash_init(page_access_hash);
	printk(KERN_INFO "Page access tracking hashtable initialized\n");

	/* Resolve the bulk migration API dynamically */
	pt_uts_migrate_file_pages_bulk_vec = (uts_migrate_vec_t)lookup_external_symbol("uts_migrate_file_pages_bulk_vec");
	if (!pt_uts_migrate_file_pages_bulk_vec) {
		pr_err("KTMM Error: Could not resolve 'uts_migrate_file_pages_bulk_vec'. Migration will be disabled.\n");
	} else {
		pr_info("KTMM: 'uts_migrate_file_pages_bulk_vec' resolved at %p\n", pt_uts_migrate_file_pages_bulk_vec);
	}

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

static void page_access_hash_cleanup(void)
{
	struct page_access_entry *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long entry_count = 0;
	
	spin_lock(&page_access_lock);
	
	hash_for_each_safe(page_access_hash, bkt, tmp, entry, hash_node) {
		hash_del(&entry->hash_node);
		kfree(entry);
		entry_count++;
	}
	
	spin_unlock(&page_access_lock);
	
	printk(KERN_INFO "Page access hashtable cleaned up, freed %lu entries\n", entry_count);
}

void tmemd_stop_all(void)
{
	int nid;

	for_each_online_node(nid)
	{
		kthread_stop(tmemd_list[nid]);
	}

	uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
	
	page_access_hash_cleanup();
}