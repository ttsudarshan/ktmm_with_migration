/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 *
 *  Migration logic adapted from uts_migrate.c (kernel 5.14) for kernel 6.1
 *  v9: migrates ALL LRU page types -- anonymous, file-backed, shmem, and
 *      large folios (THP). Only DMA-pinned folios are skipped.
 *
 *  Anon-safety rules (read before touching migration code):
 *    1. Destination folio order MUST equal source order. migrate_pages()
 *       copies folio_nr_pages(src) pages into dst with no size check; an
 *       order-0 dst for a THP silently corrupts memory.
 *    2. NR_ISOLATED_ANON and NR_ISOLATED_FILE are accounted per folio, in
 *       PAGES. Leaving NR_ISOLATED_ANON inflated makes too_many_isolated()
 *       throttle every direct reclaimer on the node (looks like a freeze).
 *    3. migrate_pages() is called with MR_DEMOTION for BOTH directions, so
 *       the kernel never touches NR_ISOLATED (see migrate_folio_done() in
 *       6.1.133) and this module owns 100% of that accounting.
 *    4. Migration allocations use __GFP_NOMEMALLOC and no direct reclaim.
 *       tmemd runs with PF_MEMALLOC; without NOMEMALLOC it can drain the
 *       target node's emergency reserves.
 *    5. The promote list is capped (promote_max_pages) so parked isolated
 *       pages can't grow without bound.
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
 *  Tiers are chosen by module params, NOT hardcoded node ids. Current layout:
 *      dram_nid = 0  (fast tier, local DRAM)
 *      pmem_nid = 2  (slow tier, CPU-less CXL node)
 *  Node 1 (the second DRAM socket) is deliberately NOT a participant: no
 *  daemon is spawned for it, so it is never scanned, never a demote source,
 *  and never a migration target.
 *
 *  FAST/DRAM node (node_id == dram_nid):
 *    - scan_inactive_list: DEMOTE cold file pages to the slow tier
 *    - scan_active_list:   deactivate unreferenced pages (normal)
 *
 *  SLOW/PMEM node (node_id == pmem_nid, i.e. ktmm_is_pmem_node()==true):
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
 * Tier selection. Defaults target the node 0 <-> node 1 layout
 * (node 0 = fast DRAM, node 2 = CPU-less CXL slow tier). Override without
 * recompiling, e.g.:
 *     sudo insmod build/ktmm.ko pmem_nid=2 dram_nid=0
 */
static int pmem_nid = 2;   /* slow tier: CXL / PMEM */
static int dram_nid = 0;   /* fast tier: local DRAM */
module_param(pmem_nid, int, 0444);
MODULE_PARM_DESC(pmem_nid, "NUMA node id used as the slow (CXL/PMEM) tier");
module_param(dram_nid, int, 0444);
MODULE_PARM_DESC(dram_nid, "NUMA node id used as the fast (DRAM) tier");

/*
 * Max pages parked (isolated) on the promote list at once. Anon volume is far
 * larger than file volume, so without a cap NR_ISOLATED_ANON on the slow node
 * can grow until reclaim throttles. Tunable at runtime via
 * /sys/module/ktmm/parameters/promote_max_pages.
 */
static unsigned long promote_max_pages = 4096;
module_param(promote_max_pages, ulong, 0644);
MODULE_PARM_DESC(promote_max_pages, "Max pages held on the promote list");

/*
 * Overflow onto the slow tier instead of OOM. When the fast nodes can't
 * satisfy an order-0 allocation, retry with the slow node allowed.
 *   1 (default): fast nodes first, CXL as last resort before OOM
 *   0          : strict -- slow node only gets pages via demotion or an
 *                explicit bind to it alone (old behaviour)
 * Runtime tunable: /sys/module/ktmm/parameters/pmem_fallback
 */
static bool pmem_fallback = true;
module_param(pmem_fallback, bool, 0644);
MODULE_PARM_DESC(pmem_fallback, "Overflow order-0 allocations onto the slow tier instead of OOM");

static inline void set_pmem_node_id(int nid) { pmem_node_id = nid; }
static inline void set_pmem_node(int nid)    { (void)nid; }  /* was: pgdat->pm_node */
static inline void set_ktmm_scan(void)       { }            /* was: kernel reclaim toggle */

/* True once a sane slow-tier node id has been set. */
static inline bool ktmm_pmem_node_valid(void)
{
	return pmem_node_id >= 0 && pmem_node_id < MAX_NUMNODES;
}

/* Is this pgdat the logical slow (PMEM) tier? Compares against the
 * module-selected pmem_node_id (set from the pmem_nid param at init). */
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

/*
 * prep_transhuge_page() is not exported. Needed to set up order>1 destination
 * folios exactly like __folio_alloc() does (we can't call __folio_alloc()
 * because it goes through the hooked __alloc_pages and would be steered off
 * the slow node). If unresolved, large folios are split and migrated as base
 * pages instead.
 */
static void (*pt_prep_transhuge_page)(struct page *page);

static struct task_struct *tmemd_list[MAX_NUMNODES];
wait_queue_head_t tmemd_wait[MAX_NUMNODES];


/*****************************************************************************
 * PERSISTENT PROMOTE LIST (per-node)
 *
 * This is our own list, NOT a kernel LRU. Pages sit here between scan cycles
 * waiting to be migrated to DRAM by scan_promote_list().
 *
 * Pages on this list are still counted in NR_ISOLATED_ANON or NR_ISOLATED_FILE
 * (per folio_is_file_lru()) on their source node. scan_promote_list()
 * decrements the matching counter when it processes them (either by
 * successful migration or by putting them back on LRU).
 *****************************************************************************/

struct ktmm_promote_list {
  struct list_head head;
  spinlock_t       lock;
  unsigned long    nr_pages;   /* in PAGES, not folios (THP = 512) */
};


static struct ktmm_promote_list promote_lists[MAX_NUMNODES];

static void init_promote_list(int nid)
{
  INIT_LIST_HEAD(&promote_lists[nid].head);
  spin_lock_init(&promote_lists[nid].lock);
  promote_lists[nid].nr_pages = 0;
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
  long nr_anon = 0, nr_file = 0;

  spin_lock(&pli->lock);
  while (!list_empty(&pli->head)) {
    struct folio *folio = lru_to_folio(&pli->head);
    long nr = folio_nr_pages(folio);

    list_del_init(&folio->lru);
    pli->nr_pages -= nr;
    spin_unlock(&pli->lock);

    /* Read the type BEFORE putback: putback drops our isolation ref. */
    if (folio_is_file_lru(folio))
      nr_file += nr;
    else
      nr_anon += nr;

    ktmm_folio_putback_lru(folio);

    spin_lock(&pli->lock);
  }
  spin_unlock(&pli->lock);

  /* Not under an irq-disabled lock here, so use the irq-safe variant. */
  if (nr_anon)
    mod_node_page_state(pgdat, NR_ISOLATED_ANON, -nr_anon);
  if (nr_file)
    mod_node_page_state(pgdat, NR_ISOLATED_FILE, -nr_file);

  if (nr_anon || nr_file)
    printk(KERN_INFO "KTMM: Drained promote list on node %d: anon=%ld file=%ld pages\n",
           nid, nr_anon, nr_file);
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
static atomic64_t migrate_filter_pinned = ATOMIC64_INIT(0);    /* folios */
static atomic64_t migrate_attempted_anon = ATOMIC64_INIT(0);   /* pages */
static atomic64_t migrate_attempted_file = ATOMIC64_INIT(0);   /* pages (incl. shmem) */
static atomic64_t migrate_attempted_large = ATOMIC64_INIT(0);  /* folios */
static atomic64_t promote_list_full = ATOMIC64_INIT(0);        /* folios kept active */
static atomic64_t migrate_attempted = ATOMIC64_INIT(0);        /* pages */
static atomic64_t migrate_success = ATOMIC64_INIT(0);
static atomic64_t migrate_alloc_fail = ATOMIC64_INIT(0);

/* Allocations that overflowed onto the slow tier (pmem_fallback) */
static atomic64_t alloc_pmem_fallback = ATOMIC64_INIT(0);

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

  u64 filter_pinned = atomic64_read(&migrate_filter_pinned);
  u64 att_anon = atomic64_read(&migrate_attempted_anon);
  u64 att_file = atomic64_read(&migrate_attempted_file);
  u64 att_large = atomic64_read(&migrate_attempted_large);
  u64 plist_full = atomic64_read(&promote_list_full);
  u64 mig_attempted = atomic64_read(&migrate_attempted);
  u64 mig_success = atomic64_read(&migrate_success);
  u64 alloc_fail = atomic64_read(&migrate_alloc_fail);

  /* Promote list depth snapshot */
  unsigned long plist_depth = 0;
  int nid;

  for_each_online_node(nid) {
    if (nid == pmem_node_id)
      plist_depth += READ_ONCE(promote_lists[nid].nr_pages);
  }

  printk(KERN_INFO "*** KTMM PAGE STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
         promoted, demoted);

  printk(KERN_INFO "*** KTMM 3-STAGE PIPELINE ***\n");
  printk(KERN_INFO "  Stage 1 (inactive->active):  %llu\n", s1_inactive_to_active);
  printk(KERN_INFO "  Stage 2 (active->promote):   %llu\n", s2_active_to_promote);
  printk(KERN_INFO "  Stage 3 (promote->DRAM):     %llu\n", s3_promote_to_dram);
  printk(KERN_INFO "  Promote list depth (pages):  %lu / %lu (full-skips=%llu)\n",
         plist_depth, promote_max_pages, plist_full);

  printk(KERN_INFO "*** KTMM PAGE FLOW DEBUG ***\n");
  printk(KERN_INFO "  Scanned: inactive=%llu, active=%llu, promote=%llu\n",
         scanned_inactive, scanned_active, scanned_promote);
  printk(KERN_INFO "  Deactivated (active->inactive): %llu\n", active_to_inactive);
  printk(KERN_INFO "  Demote candidates: %llu\n", demo_cand);

  printk(KERN_INFO "*** KTMM MIGRATION DEBUG ***\n");
  printk(KERN_INFO "  Attempted pages: anon=%llu, file=%llu | large folios=%llu | pinned skipped=%llu\n",
         att_anon, att_file, att_large, filter_pinned);
  printk(KERN_INFO "  Migrate: attempted=%llu, success=%llu, alloc_fail=%llu\n",
         mig_attempted, mig_success, alloc_fail);
  printk(KERN_INFO "  Alloc overflow onto slow tier: %llu pages\n",
         (u64)atomic64_read(&alloc_pmem_fallback));
  printk(KERN_INFO "*** END DEBUG ***\n");

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

static inline bool ktmm_folio_can_migrate(struct folio *folio);

/**
 * ktmm_alloc_migrate_page - Allocate page on target node for migration
 *
 * Calls pt_alloc_pages DIRECTLY to bypass our hooked __alloc_pages.
 */
static struct page *ktmm_alloc_migrate_page(struct page *page, unsigned long private)
{
  /* private carries the target nid (passed as unsigned long by migrate_pages).
   * Safe for the small node ids we use (0,2); revisit if node ids exceed INT_MAX. */
  int nid = (int)private;
  struct folio *src = page_folio(page);
  unsigned int order = 0;
  struct page *newpage;
  nodemask_t nodemask;
  /*
   * Same flags upstream demotion uses (demote_folio_list): no direct reclaim,
   * may wake kswapd, never touch emergency reserves (we run with PF_MEMALLOC).
   */
  gfp_t gfp = (GFP_HIGHUSER_MOVABLE & ~__GFP_RECLAIM) | __GFP_NOWARN |
              __GFP_NOMEMALLOC | GFP_NOWAIT;

  if (folio_test_large(src)) {
    order = folio_order(src);

    /*
     * Can't build a proper order>1 folio without prep_transhuge_page().
     * Returning NULL makes migrate_pages() split the folio and retry the
     * base pages (allowed because we pass MR_DEMOTION, not MR_NUMA_MISPLACED).
     */
    if (order > 1 && !pt_prep_transhuge_page) {
      atomic64_inc(&migrate_alloc_fail);
      return NULL;
    }

    /* Mirrors alloc_migration_target(), minus direct reclaim. Includes
     * __GFP_COMP, __GFP_NOMEMALLOC and __GFP_NOWARN. */
    gfp = GFP_TRANSHUGE_LIGHT;
  }

  nodes_clear(nodemask);
  node_set(nid, nodemask);

  /* Destination order MUST match source order (see header rule 1). */
  newpage = pt_alloc_pages(gfp, order, nid, &nodemask);

  if (!newpage) {
    atomic64_inc(&migrate_alloc_fail);
    return NULL;
  }

  if (order > 1)
    pt_prep_transhuge_page(newpage);   /* same as __folio_alloc() */

  return newpage;
}

/**
 * ktmm_free_migrate_page - Free page on migration failure
 */
static void ktmm_free_migrate_page(struct page *page, unsigned long private)
{
  /* folio_put, not __free_pages(page, 0): dst may be a compound folio. */
  folio_put(page_folio(page));
}

/**
 * ktmm_migrate_folio_list - Migrate already-isolated folios of any type
 *
 * Anon, file, shmem and large folios are all migrated. DMA-pinned folios are
 * left on @folio_list for the caller to put back. Folios that fail migration
 * are put back to the LRU here. NR_ISOLATED is NOT touched here or by the
 * kernel (MR_DEMOTION); callers own it.
 */
static int ktmm_migrate_folio_list(struct list_head *folio_list, int target_nid,
           unsigned long *nr_succeeded_out)
{
  LIST_HEAD(pagelist);
  struct folio *folio, *next;
  unsigned int nr_succeeded = 0;
  unsigned long nr_to_migrate = 0;   /* pages */
  int ret;

  if (nr_succeeded_out)
    *nr_succeeded_out = 0;

  if (list_empty(folio_list))
    return 0;

  list_for_each_entry_safe(folio, next, folio_list, lru) {
    long nr = folio_nr_pages(folio);

    if (!ktmm_folio_can_migrate(folio)) {
      atomic64_inc(&migrate_filter_pinned);
      continue;
    }

    if (folio_test_large(folio))
      atomic64_inc(&migrate_attempted_large);
    if (folio_test_anon(folio))
      atomic64_add(nr, &migrate_attempted_anon);
    else
      atomic64_add(nr, &migrate_attempted_file);

    list_move_tail(&folio->lru, &pagelist);
    nr_to_migrate += nr;
  }

  if (nr_to_migrate == 0)
    return 0;

  atomic64_add(nr_to_migrate, &migrate_attempted);

  /*
   * MR_DEMOTION for both directions: in 6.1.133 migrate_folio_done() skips
   * the NR_ISOLATED decrement only for MR_DEMOTION. With MR_NUMA_MISPLACED
   * the kernel decremented successes AND our callers decremented them again.
   * It also lets migrate_pages() split a large folio when the large dst
   * allocation fails, instead of giving up on it.
   */
  ret = pt_migrate_pages(&pagelist,
          ktmm_alloc_migrate_page,
          ktmm_free_migrate_page,
          (unsigned long)target_nid,
          MIGRATE_SYNC,
          MR_DEMOTION,
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
 * Steers normal allocations to the fast nodes (preserves the old
 * __GFP_PMEM-era behaviour without the custom GFP flag). Migration
 * allocations bypass this hook via ktmm_alloc_migrate_page().
 *
 * Rules, in order:
 *   1. The caller's nodemask (numactl --membind, mbind()) is RESPECTED;
 *      we only remove the slow node from it.
 *   2. Bound to ONLY the slow node (--membind=2): honored as-is.
 *   3. Otherwise try the fast nodes first. If that fails and the caller is
 *      allowed on the slow node, overflow onto it instead of OOM-killing
 *      (pmem_fallback=1, order-0 only).
 *
 * The first attempt drops __GFP_DIRECT_RECLAIM (kswapd is still woken).
 * Without that, a full fast tier would go through direct reclaim and the
 * OOM killer inside the first call and never reach the fallback. This
 * matches stock Linux with zone_reclaim_mode=0, which also spills to a
 * remote node before reclaiming locally.
 */
static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
          nodemask_t *nodemask)
{
  nodemask_t mask;
  struct page *page;

  if (!ktmm_pmem_node_valid())
    return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);

  if (nodemask)
    mask = *nodemask;                    /* keep numactl / mempolicy (struct copy; 6.1 has no nodes_copy) */
  else
    mask = node_states[N_MEMORY];

  node_clear(pmem_node_id, mask);

  /* Rule 2: explicitly bound to ONLY the slow node */
  if (nodes_empty(mask))
    return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);

  /*
   * Fast nodes only (old behaviour) when: fallback disabled, high-order
   * (callers like THP faults fall back to order-0 themselves, so big
   * folios never land on CXL this way), __GFP_NOFAIL (needs direct
   * reclaim), or the caller's own mask excludes the slow node.
   */
  if (!pmem_fallback || order > 0 || (gfp_mask & __GFP_NOFAIL) ||
      (nodemask && !node_isset(pmem_node_id, *nodemask)))
    return pt_alloc_pages(gfp_mask, order, preferred_nid, &mask);

  /* Rule 3: fast nodes first, no direct reclaim, no failure splat */
  page = pt_alloc_pages((gfp_mask & ~__GFP_DIRECT_RECLAIM) | __GFP_NOWARN,
                        order, preferred_nid, &mask);
  if (page)
    return page;

  /* Fast tier full: overflow onto the slow node (original mask/flags) */
  atomic64_inc(&alloc_pmem_fallback);
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

/*
 * Any LRU folio is a migration candidate: anon, file, shmem, large.
 * DMA-pinned folios (RDMA/GPU/io_uring buffers) can't move: migrate_pages()
 * would unmap them, fail the refcount check, and remap -- pure waste.
 */
static inline bool ktmm_folio_can_migrate(struct folio *folio)
{
  return !folio_maybe_dma_pinned(folio);
}


/*****************************************************************************
 * LIST SCANNING FUNCTIONS — 3-STAGE PIPELINE
 *
 * FAST/DRAM node (node_id == dram_nid):
 *   - scan_inactive_list: DEMOTE cold file pages to the slow tier
 *   - scan_active_list:   deactivate unreferenced pages
 *
 * SLOW/PMEM node (node_id == pmem_nid):
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
 * Drains up to nr_to_scan PAGES from the per-node promote list and
 * migrates them to the DRAM node (dram_nid). Pages that fail migration or
 * filter checks are put back on their original LRU.
 *
 * NR_ISOLATED accounting: these pages were counted as isolated when
 * they were first removed from the active LRU in scan_active_list().
 * We decrement NR_ISOLATED_ANON / NR_ISOLATED_FILE here, per folio type,
 * for all pages we process.
 */
static unsigned long scan_promote_list(unsigned long nr_to_scan,
           struct pglist_data *pgdat)
{
  struct ktmm_promote_list *pli = &promote_lists[pgdat->node_id];
  LIST_HEAD(l_migrate);
  struct folio *folio, *next;
  unsigned long nr_taken = 0;       /* pages */
  unsigned long nr_migrated = 0;
  long nr_anon = 0, nr_file = 0;    /* pages, for NR_ISOLATED_* */
  int target_node = dram_nid;  /* promote to the fast DRAM tier */

  if (!ktmm_is_pmem_node(pgdat))
    return 0;

  /*
   * Take pages off the promote list. We hold our own spinlock,
   * NOT the lruvec lock — these pages are on our private list.
   */
  spin_lock(&pli->lock);
  while (nr_taken < nr_to_scan && !list_empty(&pli->head)) {
    long nr;

    folio = lru_to_folio(&pli->head);
    nr = folio_nr_pages(folio);

    /*
     * Record type now: after migrate_pages() a successfully migrated
     * source folio may already be freed. Isolated folios can't be split
     * by others (our ref blocks it) or change LRU type, so this is stable.
     */
    if (folio_is_file_lru(folio))
      nr_file += nr;
    else
      nr_anon += nr;

    list_del_init(&folio->lru);
    list_add(&folio->lru, &l_migrate);
    nr_taken += nr;
    pli->nr_pages -= nr;
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
    printk(KERN_INFO "KTMM: [Stage 3] Promoted %lu pages promote->DRAM\n",
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
   * Decrement the NR_ISOLATED counts left elevated by scan_active_list.
   * No irq-disabled lock is held here, so use the irq-safe variant.
   */
  if (nr_anon)
    mod_node_page_state(pgdat, NR_ISOLATED_ANON, -nr_anon);
  if (nr_file)
    mod_node_page_state(pgdat, NR_ISOLATED_FILE, -nr_file);

  return nr_migrated;
}


/**
 * scan_active_list - Stage 2: active -> promote list (PMEM)
 *
 * On PMEM node: referenced pages (anon or file) are ENQUEUED onto the
 * persistent promote list (NOT migrated here), up to promote_max_pages. They'll be migrated
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
  int referenced;            /* cached folio_referenced() result (see loop) */
  LIST_HEAD(l_hold);
  LIST_HEAD(l_active);
  LIST_HEAD(l_inactive);
  LIST_HEAD(l_to_promote);   /* local batch before adding to promote list */
  __maybe_unused unsigned nr_deactivate, nr_activate;
  __maybe_unused unsigned nr_rotated = 0;
  unsigned long nr_enqueued = 0;  /* PAGES added to promote list */
  unsigned long depth = 0;
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
     * Evaluate references ONCE. folio_referenced() clears the PTE accessed
     * bits as a side effect, so calling it twice on the same folio corrupts
     * the signal -- the second call sees the bits the first already cleared
     * and reports the page as cold. Capture the result and reuse it for every
     * decision below. (This was the bug: the old code called it here AND again
     * in the "keep active" branch.)
     */
    referenced = ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup,
                                       &vm_flags);

    /*
     * SLOW/PMEM NODE — Stage 2: referenced pages go to the promote list.
     * Collect into l_to_promote first, then bulk-add to the persistent
     * promote list under one lock acquisition.
     */
    if (is_pmem_node && referenced && ktmm_folio_can_migrate(folio)) {
      long nr = folio_nr_pages(folio);

      /* Only this node's tmemd writes nr_pages, so an unlocked read is fine. */
      if (READ_ONCE(promote_lists[nid].nr_pages) + nr_enqueued + nr <=
          promote_max_pages) {
        list_add(&folio->lru, &l_to_promote);
        nr_enqueued += nr;
        atomic64_add(nr, &pages_active_to_promote);
        continue;
      }

      /* Promote list full: keep it active, it gets another shot next cycle. */
      atomic64_inc(&promote_list_full);
      nr_rotated += nr;
      list_add(&folio->lru, &l_active);
      continue;
    }

    /* Referenced executable file pages: keep active (rotate). */
    if (referenced && (vm_flags & VM_EXEC) && folio_is_file_lru(folio)) {
      nr_rotated += folio_nr_pages(folio);
      list_add(&folio->lru, &l_active);
      continue;
    }

    /* Not referenced (or not worth keeping active): deactivate */
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
    pli->nr_pages += nr_enqueued;
    depth = pli->nr_pages;
    spin_unlock(&pli->lock);

    printk(KERN_INFO "KTMM: [Stage 2] Enqueued %lu %s pages active->promote (depth=%lu)\n",
           nr_enqueued, file ? "file" : "anon", depth);
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
   * (nr_taken - nr_enqueued). Both are in pages. All folios here came from
   * one LRU, so they share the anon/file type used below.
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
 * On PMEM node: ACTIVATE referenced pages (anon or file). They'll be
 * picked up by scan_active_list (Stage 2) in the next scan cycle.
 *
 * On DRAM node: DEMOTE cold (unreferenced) pages (anon or file) to PMEM.
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
      int can_migrate = ktmm_folio_can_migrate(folio);

      /*
       * PMEM NODE — Stage 1: Activate referenced pages.
       * They'll move to the active list, then get picked up by
       * scan_active_list (Stage 2) in the next scan cycle.
       */
      if (is_pmem_node && is_referenced && can_migrate) {
        list_del(&folio->lru);
        folio_set_active(folio);
        list_add(&folio->lru, &l_active);
        nr_activate++;
        atomic64_inc(&pages_inactive_to_active);
        continue;
      }

      /*
       * DRAM NODE: Cold (unreferenced) pages get demoted.
       */
      if (is_dram_node && pmem_node_id != -1 && !is_referenced && can_migrate) {
        list_del(&folio->lru);
        list_add(&folio->lru, &l_demote);
        atomic64_inc(&demote_candidates);
        continue;
      }

      /* Leave other pages in folio_list for putback */
    }
  }

  /*
   * DRAM NODE: Demote cold pages to PMEM
   */
  if (is_dram_node && !list_empty(&l_demote)) {
    int target_node = pmem_node_id;

    ktmm_migrate_folio_list(&l_demote, target_node, &nr_migrated);

    if (nr_migrated > 0) {
      atomic64_add(nr_migrated, &total_pages_demoted);
      printk(KERN_INFO "KTMM: Demoted %lu %s pages DRAM->PMEM\n",
             nr_migrated, file ? "file" : "anon");
    }
  }

  spin_lock_irq(&lruvec->lru_lock);

  if (nr_activate > 0) {
    ktmm_move_folios_to_lru(lruvec, &l_active);
    if (is_pmem_node)
      printk(KERN_INFO "KTMM: [Stage 1] Activated %lu folios inactive->active\n",
             nr_activate);
      ;  // log removed: empty statement keeps the braceless control valid
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
      ;  // log removed: empty statement keeps the braceless control valid

    /* Needed to build order>1 destination folios for THP migration. */
    pt_prep_transhuge_page = (void *)symbol_lookup("prep_transhuge_page");
    if (!pt_prep_transhuge_page && kln)
      pt_prep_transhuge_page = (void *)kln("prep_transhuge_page");
    if (!pt_prep_transhuge_page)
      pr_warn("KTMM: prep_transhuge_page unresolved; large folios will be split before migrating\n");
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

  printk(KERN_INFO "*** KTMM FINAL: Promoted: %llu, Demoted: %llu ***\n",
         (u64)atomic64_read(&total_pages_promoted),
         (u64)atomic64_read(&total_pages_demoted));

  printk(KERN_INFO "*** KTMM 3-STAGE PIPELINE FINAL ***\n");
  printk(KERN_INFO "  Stage 1 (inactive->active):  %llu\n",
         (u64)atomic64_read(&pages_inactive_to_active));
  printk(KERN_INFO "  Stage 2 (active->promote):   %llu\n",
         (u64)atomic64_read(&pages_active_to_promote));
  printk(KERN_INFO "  Stage 3 (promote->DRAM):     %llu\n",
         (u64)atomic64_read(&pages_promote_to_dram));

  printk(KERN_INFO "*** KTMM Migration: attempted=%llu (anon=%llu file=%llu), success=%llu, alloc_fail=%llu ***\n",
         (u64)atomic64_read(&migrate_attempted),
         (u64)atomic64_read(&migrate_attempted_anon),
         (u64)atomic64_read(&migrate_attempted_file),
         (u64)atomic64_read(&migrate_success),
         (u64)atomic64_read(&migrate_alloc_fail));

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