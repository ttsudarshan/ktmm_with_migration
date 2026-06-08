/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 *
 *  Migration logic adapted from uts_migrate.c (kernel 5.14) for kernel 6.1
 *  ONLY migrates file-backed pages (skips anonymous pages)
 *
 *  v8: 3-STAGE PROMOTION PIPELINE
 *
 *  At every scan cycle (time t), three movements happen concurrently on PMEM:
 *
 *    Stage 1: scan_inactive_list  - p pages move  inactive  -> active
 *    Stage 2: scan_active_list    - m pages move  active    -> promote list
 *    Stage 3: scan_promote_list   - n pages move  promote   -> DRAM
 *
 *  The promote list is a persistent per-node list (NOT a kernel LRU) so
 *  ktmm_move_folios_to_lru() cannot interfere with it. Pages are kept
 *  isolated while on the promote list; NR_ISOLATED is adjusted when they
 *  finally migrate or get put back.
 *
 *  DRAM (node 0, pm_node=0):
 *    - scan_inactive_list: DEMOTE cold file pages to PMEM
 *    - scan_active_list:   deactivate unreferenced pages (normal)
 *
 *  PMEM (node 1, pm_node!=0):
 *    - scan_promote_list:  MIGRATE promote list pages to DRAM   (stage 3)
 *    - scan_active_list:   ENQUEUE hot file pages to promote    (stage 2)
 *    - scan_inactive_list: ACTIVATE referenced file pages       (stage 1)
 */

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

#define TMEMD_GFP_FLAGS GFP_NOIO

int pmem_node = -1;

/* =====================================================================
 * PATCH-FREE SHIMS
 * These replace kernel-side additions the old patched tree provided
 * (pm_node field, pmem_node_id global, set_* helpers, __GFP_PMEM,
 *  NR_PROMOTED/NR_DEMOTED, exported migrate_pages). Nothing here needs
 * a kernel rebuild.
 * ===================================================================== */

/* Logical PMEM node id, chosen by the module (no kernel pm_node field). */
#include <linux/moduleparam.h>

static int pmem_node_id = -1;

/*
 * Tier selection. Defaults target THIS machine's layout (node 0 = local DRAM,
 * node 2 = CPU-less CXL). Override without recompiling, e.g.:
 *     sudo insmod build/ktmm.ko pmem_nid=2 dram_nid=0
 */
static int pmem_nid = 2;   /* slow tier: CXL / PMEM */
static int dram_nid = 0;   /* fast tier: local DRAM */
module_param(pmem_nid, int, 0444);
MODULE_PARM_DESC(pmem_nid, "NUMA node id used as the slow (CXL/PMEM) tier");
module_param(dram_nid, int, 0444);
MODULE_PARM_DESC(dram_nid, "NUMA node id used as the fast (DRAM) tier");
static inline void set_pmem_node_id(int nid) { pmem_node_id = nid; }
static inline void set_pmem_node(int nid)    { (void)nid; }  /* was: pgdat->pm_node */
static inline void set_ktmm_scan(void)       { }            /* was: kernel reclaim toggle */

/* Replaces "pgdat->pm_node != 0": is this the logical PMEM node? */
static inline bool ktmm_is_pmem_node(struct pglist_data *pgdat)
{
	return pgdat->node_id == pmem_node_id;
}

/* ---------------------------------------------------------------------
 * struct scan_control is PRIVATE to mm/vmscan.c -- there is no public
 * header for it. The hooked isolate_lru_folios() reads fields out of the
 * pointer we hand it, so this MUST match the kernel's binary layout for
 * THIS exact kernel. VERIFY against your tree and replace if different:
 *
 *   sed -n '/^struct scan_control {/,/^};/p' \
 *       /home/tiwari/linux-6.1.133/mm/vmscan.c
 *
 * A mismatch = silent memory corruption, so do not skip this check.
 * (Layout below is mainline 6.1.)
 * --------------------------------------------------------------------- */
struct scan_control {
	unsigned long nr_to_reclaim;
	nodemask_t	*nodemask;
	struct mem_cgroup *target_mem_cgroup;
	unsigned long	anon_cost;
	unsigned long	file_cost;
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
	unsigned int may_deactivate:2;
	unsigned int force_deactivate:1;
	unsigned int skipped_deactivate:1;
	unsigned int may_writepage:1;
	unsigned int may_unmap:1;
	unsigned int may_swap:1;
	unsigned int proactive:1;
	unsigned int memcg_low_reclaim:1;
	unsigned int memcg_low_skipped:1;
	unsigned int hibernation_mode:1;
	unsigned int compaction_ready:1;
	unsigned int cache_trim_mode:1;
	unsigned int file_is_tiny:1;
	unsigned int no_demotion:1;
#ifdef CONFIG_LRU_GEN
	/* help kswapd make better choices among multiple memcgs */
	unsigned int memcgs_need_aging:1;
	unsigned long last_reclaimed;
#endif
	s8 order;
	s8 priority;
	s8 reclaim_idx;
	gfp_t gfp_mask;
	unsigned long nr_scanned;
	unsigned long nr_reclaimed;
	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;
	struct reclaim_state reclaim_state;
};

/* migrate_pages() is not exported to modules; resolve it like the hooks. */
static int (*pt_migrate_pages)(struct list_head *l, new_page_t new,
		free_page_t free, unsigned long private,
		enum migrate_mode mode, int reason,
		unsigned int *ret_succeeded);

/*
 * buffer_heads_over_limit is an unexported kernel data symbol (a variable,
 * so the kprobe-based symbol_lookup() can't resolve it). We bootstrap
 * kallsyms_lookup_name() at init to get its address and read the live value,
 * preserving the original active-list behaviour exactly.
 */
static int *pt_buffer_heads_over_limit;

static struct task_struct *tmemd_list[MAX_NUMNODES];
wait_queue_head_t tmemd_wait[MAX_NUMNODES];


/*****************************************************************************
 * PERSISTENT PROMOTE LIST (per-node)
 *
 * This is our own list, NOT a kernel LRU. Pages sit here between scan cycles
 * waiting to be migrated to DRAM by scan_promote_list().
 *
 * Pages on this list are still counted in NR_ISOLATED_FILE on their source
 * node. scan_promote_list() decrements NR_ISOLATED when it processes them
 * (either by successful migration or by putting them back on LRU).
 *****************************************************************************/

struct ktmm_promote_list {
  struct list_head head;
  spinlock_t       lock;
  unsigned long    count;
};


static struct ktmm_promote_list promote_lists[MAX_NUMNODES];

static void init_promote_list(int nid)
{
  INIT_LIST_HEAD(&promote_lists[nid].head);
  spin_lock_init(&promote_lists[nid].lock);
  promote_lists[nid].count = 0;
}

/**
 * drain_promote_list - put back all pages on promote list to their LRU
 *
 * Called during module cleanup to ensure no pages are left stranded.
 */
static void (*pt_folio_putback_lru)(struct folio *folio);

static void ktmm_folio_putback_lru(struct folio *folio)
{
  pt_folio_putback_lru(folio);
}
static void drain_promote_list(int nid, struct pglist_data *pgdat)
{
  struct ktmm_promote_list *pli = &promote_lists[nid];
  unsigned long nr_drained = 0;

  spin_lock(&pli->lock);
  while (!list_empty(&pli->head)) {
    struct folio *folio = lru_to_folio(&pli->head);

    list_del_init(&folio->lru);
    pli->count--;
    spin_unlock(&pli->lock);

    ktmm_folio_putback_lru(folio);
    nr_drained++;

    spin_lock(&pli->lock);
  }
  spin_unlock(&pli->lock);

  if (nr_drained > 0) {
    /* These pages were counted as isolated; fix the count */
    __mod_node_page_state(pgdat, NR_ISOLATED_FILE, -(long)nr_drained);
    // printk(KERN_INFO "KTMM: Drained %lu pages from promote list on node %d\n",
    //        nr_drained, nid);
  }
}


/*****************************************************************************
 * Promotion/Demotion Page Counters
 *****************************************************************************/

static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);

/*****************************************************************************
 * Page Flow Debug Counters — 3-Stage Pipeline
 *****************************************************************************/

/* Stage 1: inactive -> active (PMEM) */
static atomic64_t pages_inactive_to_active = ATOMIC64_INIT(0);

/* Stage 2: active -> promote list (PMEM) */
static atomic64_t pages_active_to_promote = ATOMIC64_INIT(0);

/* Stage 3: promote list -> DRAM (PMEM) */
static atomic64_t pages_promote_to_dram = ATOMIC64_INIT(0);

/* Other flow counters */
static atomic64_t pages_active_to_inactive = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);

/* DRAM demotion */
static atomic64_t demote_candidates = ATOMIC64_INIT(0);

/* Migration debug counters */
static atomic64_t migrate_filter_anon = ATOMIC64_INIT(0);
static atomic64_t migrate_filter_compound = ATOMIC64_INIT(0);
static atomic64_t migrate_filter_no_mapping = ATOMIC64_INIT(0);
static atomic64_t migrate_attempted = ATOMIC64_INIT(0);
static atomic64_t migrate_success = ATOMIC64_INIT(0);
static atomic64_t migrate_alloc_fail = ATOMIC64_INIT(0);

static struct timer_list page_stats_timer;

static void page_stats_timer_callback(struct timer_list *t)
{
  u64 promoted = atomic64_read(&total_pages_promoted);
  u64 demoted = atomic64_read(&total_pages_demoted);

  u64 s1_inactive_to_active = atomic64_read(&pages_inactive_to_active);
  u64 s2_active_to_promote = atomic64_read(&pages_active_to_promote);
  u64 s3_promote_to_dram = atomic64_read(&pages_promote_to_dram);

  u64 active_to_inactive = atomic64_read(&pages_active_to_inactive);
  u64 scanned_inactive = atomic64_read(&pages_scanned_inactive);
  u64 scanned_active = atomic64_read(&pages_scanned_active);
  u64 scanned_promote = atomic64_read(&pages_scanned_promote);

  u64 demo_cand = atomic64_read(&demote_candidates);

  u64 filter_anon = atomic64_read(&migrate_filter_anon);
  u64 filter_compound = atomic64_read(&migrate_filter_compound);
  u64 filter_no_mapping = atomic64_read(&migrate_filter_no_mapping);
  u64 mig_attempted = atomic64_read(&migrate_attempted);
  u64 mig_success = atomic64_read(&migrate_success);
  u64 alloc_fail = atomic64_read(&migrate_alloc_fail);

  /* Promote list depth snapshot */
  unsigned long plist_depth = 0;
  int nid;

  for_each_online_node(nid) {
    if (nid == pmem_node_id)
      plist_depth += promote_lists[nid].count;
  }

  // printk(KERN_INFO "*** KTMM PAGE STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
  //        promoted, demoted);

  // printk(KERN_INFO "*** KTMM 3-STAGE PIPELINE ***\n");
  // printk(KERN_INFO "  Stage 1 (inactive->active):  %llu\n", s1_inactive_to_active);
  // printk(KERN_INFO "  Stage 2 (active->promote):   %llu\n", s2_active_to_promote);
  // printk(KERN_INFO "  Stage 3 (promote->DRAM):     %llu\n", s3_promote_to_dram);
  // printk(KERN_INFO "  Promote list depth:          %lu\n", plist_depth);

  // printk(KERN_INFO "*** KTMM PAGE FLOW DEBUG ***\n");
  // printk(KERN_INFO "  Scanned: inactive=%llu, active=%llu, promote=%llu\n",
  //        scanned_inactive, scanned_active, scanned_promote);
  // printk(KERN_INFO "  Deactivated (active->inactive): %llu\n", active_to_inactive);
  // printk(KERN_INFO "  Demote candidates: %llu\n", demo_cand);

  // printk(KERN_INFO "*** KTMM MIGRATION DEBUG ***\n");
  // printk(KERN_INFO "  Filtered: anon=%llu, compound=%llu, no_mapping=%llu\n",
  //        filter_anon, filter_compound, filter_no_mapping);
  // printk(KERN_INFO "  Migrate: attempted=%llu, success=%llu, alloc_fail=%llu\n",
  //        mig_attempted, mig_success, alloc_fail);
  // printk(KERN_INFO "*** END DEBUG ***\n");

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



static int (*pt_folio_referenced)(struct folio *folio, int is_locked,
        struct mem_cgroup *memcg, unsigned long *vm_flags);

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



static int ktmm_folio_referenced(struct folio *folio, int is_locked,
        struct mem_cgroup *memcg, unsigned long *vm_flags)
{
  return pt_folio_referenced(folio, is_locked, memcg, vm_flags);
}


/*****************************************************************************
 * MIGRATION FUNCTIONS - Adapted from uts_migrate.c for kernel 6.1
 *****************************************************************************/

/**
 * ktmm_alloc_migrate_page - Allocate page on target node for migration
 *
 * Calls pt_alloc_pages DIRECTLY to bypass our hooked __alloc_pages.
 */
static struct page *ktmm_alloc_migrate_page(struct page *page, unsigned long private)
{
  int nid = (int)private;
  struct page *newpage;
  nodemask_t nodemask;

  nodes_clear(nodemask);
  node_set(nid, nodemask);

  newpage = pt_alloc_pages(GFP_HIGHUSER_MOVABLE, 0, nid, &nodemask);

  if (!newpage)
    atomic64_inc(&migrate_alloc_fail);

  return newpage;
}

/**
 * ktmm_free_migrate_page - Free page on migration failure
 */
static void ktmm_free_migrate_page(struct page *page, unsigned long private)
{
  __free_pages(page, 0);
}

/**
 * ktmm_migrate_folio_list - Migrate already-isolated FILE-BACKED folios
 *
 * ONLY migrates file-backed pages. Anonymous pages are SKIPPED.
 */
static int ktmm_migrate_folio_list(struct list_head *folio_list, int target_nid,
           unsigned long *nr_succeeded_out)
{
  LIST_HEAD(pagelist);
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
   * Filter: ONLY migrate file-backed pages.
   * Same filters as uts_migrate.c
   */
  list_for_each_entry_safe(folio, next, folio_list, lru) {
    /* Skip anonymous pages */
    if (folio_test_anon(folio)) {
      atomic64_inc(&migrate_filter_anon);
      continue;
    }

    /* Skip compound/huge pages */
    if (folio_test_large(folio)) {
      atomic64_inc(&migrate_filter_compound);
      continue;
    }

    /* Must have mapping (file-backed) */
    if (!folio_mapping(folio)) {
      atomic64_inc(&migrate_filter_no_mapping);
      continue;
    }

    /* File-backed page - migrate it! */
    list_del(&folio->lru);
    list_add_tail(&folio->lru, &pagelist);
    nr_to_migrate++;
  }

  if (nr_to_migrate == 0) {
    if (nr_succeeded_out)
      *nr_succeeded_out = 0;
    return 0;
  }

  atomic64_add(nr_to_migrate, &migrate_attempted);

  ret = pt_migrate_pages(&pagelist,
          ktmm_alloc_migrate_page,
          ktmm_free_migrate_page,
          (unsigned long)target_nid,
          MIGRATE_SYNC,
          MR_NUMA_MISPLACED,
          &nr_succeeded);

  atomic64_add(nr_succeeded, &migrate_success);

  /* Put back failures */
  if (!list_empty(&pagelist)) {
    struct folio *f, *f_next;

    list_for_each_entry_safe(f, f_next, &pagelist, lru) {
      list_del_init(&f->lru);
      ktmm_folio_putback_lru(f);
    }
  }

  if (nr_succeeded_out)
    *nr_succeeded_out = nr_succeeded;

  return ret;
}


/*****************************************************************************
 * ALLOC & SWAP
 *****************************************************************************/

/**
 * ktmm_alloc_pages - hooked __alloc_pages
 *
 * Keeps normal page allocations off the logical PMEM node (preserves the
 * old __GFP_PMEM-era behaviour without the custom GFP flag). Migration
 * allocations bypass this hook via ktmm_alloc_migrate_page().
 */
static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
          nodemask_t *nodemask)
{
  nodemask_t nodemask_test;
  int nid;

  if (pmem_node_id != -1) {
    nodes_clear(nodemask_test);
    for_each_node_state(nid, N_MEMORY) {
      if (nid != pmem_node_id)
        node_set(nid, nodemask_test);
    }
    nodemask = &nodemask_test;
  }

  return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);
}


/*****************************************************************************
 * Helper Functions
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

static inline bool is_file_backed_folio(struct folio *folio)
{
  return !folio_test_anon(folio) &&
         !folio_test_large(folio) &&
         folio_mapping(folio) != NULL;
}


/*****************************************************************************
 * LIST SCANNING FUNCTIONS — 3-STAGE PIPELINE
 *
 * DRAM (node 0, pm_node=0):
 *   - scan_inactive_list: DEMOTE cold file pages to PMEM
 *   - scan_active_list:   deactivate unreferenced pages
 *
 * PMEM (node 1, pm_node!=0):
 *   - scan_promote_list:  Stage 3 — migrate promote list -> DRAM
 *   - scan_active_list:   Stage 2 — enqueue hot file pages -> promote list
 *   - scan_inactive_list: Stage 1 — activate referenced file pages
 *
 * All three stages run every scan cycle, so at time t:
 *   n pages drain from promote list to DRAM   (entered promote at t-1)
 *   m pages move from active to promote list   (entered active at t-1)
 *   p pages move from inactive to active       (new arrivals)
 *****************************************************************************/

/**
 * scan_promote_list - Stage 3: migrate promote list pages to DRAM
 *
 * Drains up to nr_to_scan pages from the per-node promote list and
 * migrates them to DRAM node 0. Pages that fail migration or filter
 * checks are put back on their original LRU.
 *
 * NR_ISOLATED accounting: these pages were counted as isolated when
 * they were first removed from the active LRU in scan_active_list().
 * We decrement NR_ISOLATED here for all pages we process.
 */
static unsigned long scan_promote_list(unsigned long nr_to_scan,
           struct pglist_data *pgdat)
{
  struct ktmm_promote_list *pli = &promote_lists[pgdat->node_id];
  LIST_HEAD(l_migrate);
  struct folio *folio, *next;
  unsigned long nr_taken = 0;
  unsigned long nr_migrated = 0;
  int target_node = dram_nid;  /* promote to the fast DRAM tier */

  if (!ktmm_is_pmem_node(pgdat))
    return 0;

  /*
   * Take pages off the promote list. We hold our own spinlock,
   * NOT the lruvec lock — these pages are on our private list.
   */
  spin_lock(&pli->lock);
  while (nr_taken < nr_to_scan && !list_empty(&pli->head)) {
    folio = lru_to_folio(&pli->head);
    list_del_init(&folio->lru);
    list_add(&folio->lru, &l_migrate);
    nr_taken++;
    pli->count--;
  }
  spin_unlock(&pli->lock);

  if (nr_taken == 0)
    return 0;

  atomic64_add(nr_taken, &pages_scanned_promote);

  /*
   * Migrate to DRAM. ktmm_migrate_folio_list() handles:
   *   - re-filtering (page state may have changed since enqueue)
   *   - calling migrate_pages()
   *   - putting back failures via folio_putback_lru()
   *
   * After this call, successfully migrated pages are on DRAM LRUs
   * (handled by migrate_pages), and failures are back on PMEM LRUs
   * (handled by folio_putback_lru). Filter rejects remain in l_migrate.
   */
  ktmm_migrate_folio_list(&l_migrate, target_node, &nr_migrated);

  if (nr_migrated > 0) {
    atomic64_add(nr_migrated, &total_pages_promoted);
    atomic64_add(nr_migrated, &pages_promote_to_dram);
    printk(KERN_INFO "KTMM: [Stage 3] Promoted %lu file pages promote->DRAM\n",
           nr_migrated);
  }

  /*
   * Put back any pages that didn't pass migration filters
   * (e.g. lost their mapping between enqueue and now).
   */
  list_for_each_entry_safe(folio, next, &l_migrate, lru) {
    list_del_init(&folio->lru);
    ktmm_folio_putback_lru(folio);
  }

  /*
   * All nr_taken pages are now resolved (migrated, putback, or filter-putback).
   * Decrement the NR_ISOLATED count that was left elevated by scan_active_list.
   */
  __mod_node_page_state(pgdat, NR_ISOLATED_FILE, -(long)nr_taken);

  return nr_migrated;
}


/**
 * scan_active_list - Stage 2: active -> promote list (PMEM)
 *
 * On PMEM node: referenced file-backed pages are ENQUEUED onto the
 * persistent promote list (NOT migrated here). They'll be migrated
 * in the NEXT scan cycle by scan_promote_list().
 *
 * On DRAM node: just deactivate unreferenced pages (normal behavior).
 *
 * NR_ISOLATED: pages moved to the promote list stay counted as isolated.
 * We decrement NR_ISOLATED only for pages returned to LRU here. The
 * promote list pages' NR_ISOLATED is decremented by scan_promote_list().
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
  LIST_HEAD(l_to_promote);   /* local batch before adding to promote list */
  __maybe_unused unsigned nr_deactivate, nr_activate;
  __maybe_unused unsigned nr_rotated = 0;
  unsigned long nr_enqueued = 0;  /* pages added to promote list */
  int file = is_file_lru(lru);
  __maybe_unused int nid = pgdat->node_id;
  int is_pmem_node = ktmm_is_pmem_node(pgdat);

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

    if (unlikely(pt_buffer_heads_over_limit && *pt_buffer_heads_over_limit)) {
      if (ktmm_folio_needs_release(folio) &&
          folio_trylock(folio)) {
        filemap_release_folio(folio, 0);
        folio_unlock(folio);
      }
    }

    /*
     * PMEM NODE — Stage 2: referenced file pages go to promote list.
     * Collect into l_to_promote first, then bulk-add to the persistent
     * promote list under one lock acquisition.
     */
    if (is_pmem_node) {
      if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
        if (is_file_backed_folio(folio)) {
          list_add(&folio->lru, &l_to_promote);
          nr_enqueued++;
          atomic64_inc(&pages_active_to_promote);
          continue;
        }
      }
    }

    /* Referenced: keep active */
    if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup,
             &vm_flags) != 0) {
      if ((vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {
        nr_rotated += folio_nr_pages(folio);
        list_add(&folio->lru, &l_active);
        continue;
      }
    }

    /* Not referenced: deactivate */
    folio_clear_active(folio);
    folio_set_workingset(folio);
    list_add(&folio->lru, &l_inactive);
    atomic64_inc(&pages_active_to_inactive);
  }

  /*
   * PMEM NODE: Bulk-add collected pages to the persistent promote list.
   * These pages remain isolated (off LRU) until scan_promote_list()
   * processes them in the next scan cycle.
   */
  if (is_pmem_node && !list_empty(&l_to_promote)) {
    struct ktmm_promote_list *pli = &promote_lists[nid];

    spin_lock(&pli->lock);
    list_splice_tail(&l_to_promote, &pli->head);
    pli->count += nr_enqueued;
    spin_unlock(&pli->lock);

    // printk(KERN_INFO "KTMM: [Stage 2] Enqueued %lu file pages active->promote (depth=%lu)\n",
    //        nr_enqueued, pli->count);
  }

  /*
   * Return non-promoted pages to LRU.
   * Pages on l_to_promote are NOT returned here — they stay isolated
   * on the promote list. We adjust NR_ISOLATED accordingly.
   */
  spin_lock_irq(&lruvec->lru_lock);

  nr_activate = ktmm_move_folios_to_lru(lruvec, &l_active);
  nr_deactivate = ktmm_move_folios_to_lru(lruvec, &l_inactive);

  list_splice(&l_inactive, &l_active);

  /*
   * Decrement NR_ISOLATED for pages returned to LRU.
   * Pages enqueued to promote list stay isolated, so subtract only
   * (nr_taken - nr_enqueued).
   */
  __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file,
                        -((long)nr_taken - (long)nr_enqueued));

  spin_unlock_irq(&lruvec->lru_lock);

  ktmm_cgroup_uncharge_list(&l_active);
  ktmm_free_unref_page_list(&l_active);
}


/**
 * scan_inactive_list - Stage 1: inactive -> active (PMEM) / demote (DRAM)
 *
 * On PMEM node: ACTIVATE referenced file-backed pages. They'll be
 * picked up by scan_active_list (Stage 2) in the next scan cycle.
 *
 * On DRAM node: DEMOTE cold (unreferenced) file-backed pages to PMEM.
 */
static unsigned long scan_inactive_list(unsigned long nr_to_scan,
          struct lruvec *lruvec,
          struct scan_control *sc,
          enum lru_list lru,
          struct pglist_data *pgdat)
{
  LIST_HEAD(folio_list);
  LIST_HEAD(l_active);
  LIST_HEAD(l_demote);  /* Pages to demote to PMEM */
  unsigned long nr_scanned;
  unsigned long nr_taken = 0;
  unsigned long nr_migrated = 0;
  unsigned long nr_activate = 0;
  unsigned long vm_flags;
  bool file = is_file_lru(lru);
  __maybe_unused int nid = pgdat->node_id;
  int is_pmem_node = ktmm_is_pmem_node(pgdat);
  int is_dram_node = !ktmm_is_pmem_node(pgdat);

  ktmm_lru_add_drain();

  spin_lock_irq(&lruvec->lru_lock);

  nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
             &nr_scanned, sc, lru);

  __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

  spin_unlock_irq(&lruvec->lru_lock);

  if (nr_taken == 0)
    return 0;

  atomic64_add(nr_taken, &pages_scanned_inactive);

  /*
   * Process each folio based on node type
   */
  {
    struct folio *folio, *next;

    list_for_each_entry_safe(folio, next, &folio_list, lru) {
      int is_referenced = ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags);
      int is_file = is_file_backed_folio(folio);

      /*
       * PMEM NODE — Stage 1: Activate referenced file-backed pages.
       * They'll move to the active list, then get picked up by
       * scan_active_list (Stage 2) in the next scan cycle.
       */
      if (is_pmem_node && is_referenced && is_file) {
        list_del(&folio->lru);
        folio_set_active(folio);
        list_add(&folio->lru, &l_active);
        nr_activate++;
        atomic64_inc(&pages_inactive_to_active);
        continue;
      }

      /*
       * DRAM NODE: Cold (unreferenced) file-backed pages get demoted.
       */
      if (is_dram_node && pmem_node_id != -1 && !is_referenced && is_file) {
        list_del(&folio->lru);
        list_add(&folio->lru, &l_demote);
        atomic64_inc(&demote_candidates);
        continue;
      }

      /* Leave other pages in folio_list for putback */
    }
  }

  /*
   * DRAM NODE: Demote cold file pages to PMEM
   */
  if (is_dram_node && !list_empty(&l_demote)) {
    int target_node = pmem_node_id;

    ktmm_migrate_folio_list(&l_demote, target_node, &nr_migrated);

    if (nr_migrated > 0) {
      atomic64_add(nr_migrated, &total_pages_demoted);
      // printk(KERN_INFO "KTMM: Demoted %lu file pages DRAM->PMEM\n", nr_migrated);
    }
  }

  spin_lock_irq(&lruvec->lru_lock);

  if (nr_activate > 0) {
    ktmm_move_folios_to_lru(lruvec, &l_active);
    if (is_pmem_node)
      // printk(KERN_INFO "KTMM: [Stage 1] Activated %lu file pages inactive->active\n",
      //        nr_activate);
  }

  /* Put back pages that weren't migrated */
  if (!list_empty(&l_demote))
    ktmm_move_folios_to_lru(lruvec, &l_demote);

  ktmm_move_folios_to_lru(lruvec, &folio_list);
  __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

  spin_unlock_irq(&lruvec->lru_lock);

  ktmm_cgroup_uncharge_list(&l_active);
  ktmm_free_unref_page_list(&l_active);
  ktmm_cgroup_uncharge_list(&l_demote);
  ktmm_free_unref_page_list(&l_demote);
  ktmm_cgroup_uncharge_list(&folio_list);
  ktmm_free_unref_page_list(&folio_list);

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

  return scan_inactive_list(nr_to_scan, lruvec, sc, lru, pgdat);
}


static void scan_node(pg_data_t *pgdat,
    struct scan_control *sc,
    struct mem_cgroup_reclaim_cookie *reclaim)
{
  enum lru_list lru;
  struct mem_cgroup *memcg;
  int nid = pgdat->node_id;
  __maybe_unused int memcg_count;

  /*
   * STAGE 3 FIRST: Drain the promote list before filling it again.
   *
   * The promote list is per-node (not per-memcg), so we drain it
   * once before entering the memcg loop. This ensures that at time t:
   *   - Pages enqueued at t-1 (Stage 2) get migrated now (Stage 3)
   *   - Stage 2 below refills the list for t+1
   *   - Stage 1 below feeds the active list for t+1's Stage 2
   */
  if (ktmm_is_pmem_node(pgdat)) {
    scan_promote_list(1024, pgdat);
  }

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
 * Daemon Functions
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

  pt_migrate_pages = (void *)symbol_lookup("migrate_pages");
  if (!pt_migrate_pages) {
    pr_err("KTMM: could not resolve migrate_pages symbol\n");
    return -ENOENT;
  }

  /* Resolve the unexported buffer_heads_over_limit data symbol. */
  {
    unsigned long (*kln)(const char *);

    kln = (void *)symbol_lookup("kallsyms_lookup_name");
    if (kln)
      pt_buffer_heads_over_limit = (int *)kln("buffer_heads_over_limit");
    if (!pt_buffer_heads_over_limit)
      pr_warn("KTMM: buffer_heads_over_limit unresolved; treating as 0\n");
  }

  for (i = 0; i < MAX_NUMNODES; i++) {
    init_waitqueue_head(&tmemd_wait[i]);
    init_promote_list(i);
  }

  ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));

  timer_setup(&page_stats_timer, page_stats_timer_callback, 0);
  mod_timer(&page_stats_timer, jiffies + 5 * HZ);
  
  /* Designate the slow tier up front so no daemon races an unset value. */
  set_pmem_node_id(pmem_nid);
  set_pmem_node(pmem_nid);
  pr_info("KTMM: fast tier = node %d (DRAM), slow tier = node %d (CXL/PMEM)\n",
          dram_nid, pmem_nid);

  for_each_online_node(nid)
  {
    pg_data_t *pgdat = NODE_DATA(nid);

    /* Only the two configured tiers participate; ignore all other nodes. */
    if (nid != dram_nid && nid != pmem_nid)
      continue;

    tmemd_list[nid] = kthread_run(&tmemd, pgdat, "tmemd");
  }

  return ret;
}


void tmemd_stop_all(void)
{
  int nid;

  del_timer_sync(&page_stats_timer);

  // printk(KERN_INFO "*** KTMM FINAL: Promoted: %llu, Demoted: %llu ***\n",
  //        (u64)atomic64_read(&total_pages_promoted),
  //        (u64)atomic64_read(&total_pages_demoted));

  // printk(KERN_INFO "*** KTMM 3-STAGE PIPELINE FINAL ***\n");
  // printk(KERN_INFO "  Stage 1 (inactive->active):  %llu\n",
  //        (u64)atomic64_read(&pages_inactive_to_active));
  // printk(KERN_INFO "  Stage 2 (active->promote):   %llu\n",
  //        (u64)atomic64_read(&pages_active_to_promote));
  // printk(KERN_INFO "  Stage 3 (promote->DRAM):     %llu\n",
  //        (u64)atomic64_read(&pages_promote_to_dram));

  // printk(KERN_INFO "*** KTMM Migration: attempted=%llu, success=%llu, alloc_fail=%llu ***\n",
  //        (u64)atomic64_read(&migrate_attempted),
  //        (u64)atomic64_read(&migrate_success),
  //        (u64)atomic64_read(&migrate_alloc_fail));

  for_each_online_node(nid)
  {
    if (!IS_ERR_OR_NULL(tmemd_list[nid]))
      kthread_stop(tmemd_list[nid]);
  }

  /* Drain any remaining pages from promote lists before unhooking */
  for_each_online_node(nid)
  {
    if (nid == pmem_node_id)
      drain_promote_list(nid, NODE_DATA(nid));
  }

  uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
}