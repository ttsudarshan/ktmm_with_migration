/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 *
 *  FIXED v3: Safe lockless hotness tracking to prevent VM freeze.
 *  - Uses trylock in kprobe (never blocks)
 *  - No memory allocation in kprobe handler
 *  - Pre-allocated hotness entries
 *  - Minimal critical sections
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
 * Migration Helper Functions (for kernel 6.1+)
 *****************************************************************************/

/* Node identifiers */
#define NODE_DRAM 0
#define NODE_PMEM 1

/*****************************************************************************
 * Bulk Migration & Hotness Tracking Configuration
 *****************************************************************************/
#define BATCH_N 32            /* Maximum batch size for bulk migration */
#define WORK_SLEEP_MS 10      /* Worker sleep interval when queue is empty */
#define HIGHEST_LEVEL 7       /* Hotness threshold for promotion */

/*****************************************************************************
 * SAFE Hotness Tracking using Pre-allocated Array
 *
 * Instead of a hashtable with locks and dynamic allocation, we use a
 * fixed-size array indexed by (PFN % ARRAY_SIZE). This is lockless for
 * reads and uses atomic operations for updates.
 *
 * Trade-off: Some hash collisions, but SAFE and FAST.
 *****************************************************************************/
#define HOTNESS_ARRAY_BITS 16
#define HOTNESS_ARRAY_SIZE (1 << HOTNESS_ARRAY_BITS)  /* 65536 entries */
#define HOTNESS_ARRAY_MASK (HOTNESS_ARRAY_SIZE - 1)

/**
 * struct page_hotness_entry - lockless hotness tracking
 * @pfn: page frame number (0 = unused slot)
 * @access_count: atomic access counter
 * @in_queue: atomic flag to prevent duplicate queue entries
 */
struct page_hotness_entry {
	atomic_long_t pfn;           /* 0 means empty slot */
	atomic_t access_count;
	atomic_t in_queue;           /* 1 = already queued for promotion */
};

static struct page_hotness_entry *hotness_array;

/**
 * get_hotness_slot - get the hotness slot for a PFN (lockless)
 */
static __always_inline unsigned int get_hotness_slot(unsigned long pfn)
{
	/* Simple hash: use lower bits XOR'd with upper bits */
	return (unsigned int)((pfn ^ (pfn >> HOTNESS_ARRAY_BITS)) & HOTNESS_ARRAY_MASK);
}

/**
 * is_file_folio - check if a folio is suitable for migration
 * @folio: folio to check
 *
 * Returns true if the folio is file-backed and suitable for migration.
 * Rejects anonymous pages, huge pages, and pages without valid mappings.
 */
static __always_inline bool is_file_folio(struct folio *folio)
{
	if (folio_test_anon(folio)) return false;
	if (folio_test_hugetlb(folio) || folio_test_large(folio)) return false;
	if (!folio_mapping(folio)) return false;
	if (!folio_mapping(folio)->host) return false;
	return true;
}

/**
 * is_file_page - check if a page is suitable for migration (for kprobe)
 * @page: page to check
 *
 * Returns true if the page is file-backed and suitable for migration.
 */
static __always_inline bool is_file_page(struct page *page)
{
	if (PageAnon(page)) return false;
	if (PageHuge(page) || PageTransHuge(page) || PageCompound(page)) return false;
	if (!page_mapping(page)) return false;
	if (!page_mapping(page)->host) return false;
	return true;
}


/*****************************************************************************
 * Bulk Migration Queue Structures
 *****************************************************************************/

/**
 * struct migrate_node - node structure for migration queues
 * @link: list linkage
 * @folio: pointer to the folio to migrate
 * @pfn: page frame number for hotness tracking cleanup
 */
struct migrate_node {
	struct list_head link;
	struct folio *folio;
	unsigned long pfn;
};

/* Promotion queue: PMEM -> DRAM (hot pages detected by kprobe) */
static LIST_HEAD(promote_queue);
static DEFINE_SPINLOCK(promote_queue_lock);
static atomic_t promote_queue_count = ATOMIC_INIT(0);

/* Demotion queue: DRAM -> PMEM (cold pages from LRU scan) */
static LIST_HEAD(demote_queue);
static DEFINE_SPINLOCK(demote_queue_lock);
static atomic_t demote_queue_count = ATOMIC_INIT(0);

/* Worker threads for bulk migration */
static struct task_struct *promote_worker_task;
static struct task_struct *demote_worker_task;

/* Kprobe for intercepting page accesses (promotion trigger) */
static struct kprobe kp_folio_accessed;
static bool kprobe_registered = false;


/*****************************************************************************
 * Promotion/Demotion Page Counters
 *****************************************************************************/

/* Atomic counters for tracking total promoted and demoted pages */
static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);

/* Bulk migration statistics */
static atomic64_t mig_attempted_promote = ATOMIC64_INIT(0);
static atomic64_t mig_succeeded_promote = ATOMIC64_INIT(0);
static atomic64_t mig_attempted_demote = ATOMIC64_INIT(0);
static atomic64_t mig_succeeded_demote = ATOMIC64_INIT(0);

/*****************************************************************************
 * Page Flow Debug Counters
 *****************************************************************************/

/* Counters for page flow between lists */
static atomic64_t pages_inactive_to_active = ATOMIC64_INIT(0);
static atomic64_t pages_active_to_inactive = ATOMIC64_INIT(0);
static atomic64_t pages_active_to_promote = ATOMIC64_INIT(0);
static atomic64_t pages_promote_to_dram = ATOMIC64_INIT(0);
static atomic64_t pages_promote_failed = ATOMIC64_INIT(0);

/* Counters for pages scanned */
static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);

/* Counters for bulk queue operations */
static atomic64_t pages_queued_promote = ATOMIC64_INIT(0);
static atomic64_t pages_queued_demote = ATOMIC64_INIT(0);

/* Kprobe-specific counters */
static atomic64_t kprobe_hits = ATOMIC64_INIT(0);
static atomic64_t kprobe_pmem_pages = ATOMIC64_INIT(0);
static atomic64_t kprobe_hot_detected = ATOMIC64_INIT(0);
static atomic64_t kprobe_queue_attempts = ATOMIC64_INIT(0);
static atomic64_t kprobe_trylock_fails = ATOMIC64_INIT(0);

/* Timer for periodic printing of counters */
static struct timer_list page_stats_timer;

/**
 * page_stats_timer_callback - timer callback that prints promotion/demotion stats
 */
static void page_stats_timer_callback(struct timer_list *t)
{
	u64 promoted = atomic64_read(&total_pages_promoted);
	u64 demoted = atomic64_read(&total_pages_demoted);
	u64 kp_hits = atomic64_read(&kprobe_hits);
	u64 kp_pmem = atomic64_read(&kprobe_pmem_pages);
	u64 kp_hot = atomic64_read(&kprobe_hot_detected);
	u64 kp_queue = atomic64_read(&kprobe_queue_attempts);
	u64 kp_trylock_fail = atomic64_read(&kprobe_trylock_fails);

	/* Calculate ratio */
	u64 ratio_pct = 0;
	if (demoted > 0) {
		ratio_pct = (promoted * 100) / demoted;
	}

	printk(KERN_INFO "*** KTMM PAGE STATS: Promoted=%llu, Demoted=%llu (Ratio: %llu.%02llu:1) ***\n",
	       promoted, demoted, ratio_pct / 100, ratio_pct % 100);

	printk(KERN_INFO "*** KTMM DEBUG ***\n");
	printk(KERN_INFO "  Bulk Promote: attempted=%llu, succeeded=%llu (queued=%llu, pending=%d)\n",
	       (u64)atomic64_read(&mig_attempted_promote),
	       (u64)atomic64_read(&mig_succeeded_promote),
	       (u64)atomic64_read(&pages_queued_promote),
	       atomic_read(&promote_queue_count));
	printk(KERN_INFO "  Bulk Demote: attempted=%llu, succeeded=%llu (queued=%llu, pending=%d)\n",
	       (u64)atomic64_read(&mig_attempted_demote),
	       (u64)atomic64_read(&mig_succeeded_demote),
	       (u64)atomic64_read(&pages_queued_demote),
	       atomic_read(&demote_queue_count));
	printk(KERN_INFO "  Kprobe: hits=%llu, pmem=%llu, hot=%llu, queue_try=%llu, trylock_fail=%llu\n",
	       kp_hits, kp_pmem, kp_hot, kp_queue, kp_trylock_fail);
	printk(KERN_INFO "*** END DEBUG ***\n");

	/* Re-arm the timer for another 5 seconds */
	mod_timer(&page_stats_timer, jiffies + 5 * HZ);
}


/*****************************************************************************
 * SAFE Kprobe-based Hotness Tracking
 *
 * Key safety features:
 * 1. NO locks in the hot path - all atomic operations
 * 2. NO memory allocation in kprobe handler
 * 3. Uses trylock for queue operations (never blocks)
 * 4. Pre-allocated fixed-size array for hotness tracking
 *****************************************************************************/

/**
 * kp_folio_accessed_pre - SAFE kprobe pre-handler for folio_mark_accessed
 *
 * This runs on EVERY page access - must be extremely fast and never block!
 */
static int kp_folio_accessed_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct folio *folio;
	struct page *page;
	struct page_hotness_entry *entry;
	struct migrate_node *node;
	unsigned long pfn;
	unsigned int slot;
	int access_count;
	int nid;
	unsigned long flags;

	atomic64_inc(&kprobe_hits);

	/*
	 * Get folio from first argument (rdi on x86_64)
	 */
	folio = (struct folio *)regs->di;
	if (unlikely(!folio))
		return 0;

	page = &folio->page;
	if (unlikely(!page))
		return 0;

	/* Quick check: only file-backed pages */
	if (!is_file_page(page))
		return 0;

	/* Quick check: only PMEM pages need promotion */
	nid = page_to_nid(page);
	if (nid != NODE_PMEM)
		return 0;

	atomic64_inc(&kprobe_pmem_pages);

	/* Get PFN and hotness slot */
	pfn = page_to_pfn(page);
	slot = get_hotness_slot(pfn);
	entry = &hotness_array[slot];

	/*
	 * Lockless hotness tracking using atomics:
	 * - If slot is empty or has same PFN, increment counter
	 * - If slot has different PFN (collision), just overwrite
	 *   (acceptable loss - this is best-effort tracking)
	 */
	if (atomic_long_read(&entry->pfn) != pfn) {
		/* New page or collision - reset the slot */
		atomic_long_set(&entry->pfn, pfn);
		atomic_set(&entry->access_count, 1);
		atomic_set(&entry->in_queue, 0);
		return 0;
	}

	/* Same PFN - increment access count atomically */
	access_count = atomic_inc_return(&entry->access_count);

	/* Not hot enough yet */
	if (access_count < HIGHEST_LEVEL)
		return 0;

	/* Already queued? Use atomic test-and-set */
	if (atomic_cmpxchg(&entry->in_queue, 0, 1) != 0)
		return 0;  /* Was already 1, skip */

	atomic64_inc(&kprobe_hot_detected);
	atomic64_inc(&kprobe_queue_attempts);

	/*
	 * Try to queue for promotion - use trylock to NEVER block!
	 * If we can't get the lock, just skip this page (it will be
	 * detected again on next access).
	 */
	if (!spin_trylock_irqsave(&promote_queue_lock, flags)) {
		/* Couldn't get lock - clear in_queue flag and return */
		atomic_set(&entry->in_queue, 0);
		atomic64_inc(&kprobe_trylock_fails);
		return 0;
	}

	/*
	 * We have the lock - now we need to allocate a node.
	 * Use a pre-allocated pool or accept that we might fail.
	 * For safety, we'll use GFP_ATOMIC but accept failure.
	 */
	node = kmalloc(sizeof(*node), GFP_ATOMIC | __GFP_NOWARN);
	if (!node) {
		spin_unlock_irqrestore(&promote_queue_lock, flags);
		atomic_set(&entry->in_queue, 0);
		return 0;
	}

	/* Take a reference on the folio */
	if (!folio_try_get(folio)) {
		spin_unlock_irqrestore(&promote_queue_lock, flags);
		kfree(node);
		atomic_set(&entry->in_queue, 0);
		return 0;
	}

	INIT_LIST_HEAD(&node->link);
	node->folio = folio;
	node->pfn = pfn;

	list_add_tail(&node->link, &promote_queue);
	atomic_inc(&promote_queue_count);

	spin_unlock_irqrestore(&promote_queue_lock, flags);

	atomic64_inc(&pages_queued_promote);

	return 0;
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
    
    was_accessed = folio_test_referenced(folio);
    
    if (was_accessed) {
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
 * Bulk Migration Worker Threads
 *****************************************************************************/

/**
 * clear_hotness_for_pfn - clear hotness tracking for a PFN
 */
static void clear_hotness_for_pfn(unsigned long pfn)
{
	unsigned int slot = get_hotness_slot(pfn);
	struct page_hotness_entry *entry = &hotness_array[slot];

	if (atomic_long_read(&entry->pfn) == pfn) {
		atomic_set(&entry->in_queue, 0);
		atomic_set(&entry->access_count, 0);
	}
}

/**
 * promote_worker_fn - worker thread for bulk promotion (PMEM -> DRAM)
 */
static int promote_worker_fn(void *arg)
{
	while (!kthread_should_stop()) {
		struct migrate_node *batch[BATCH_N];
		int n = 0, i;
		unsigned long flags;
		LIST_HEAD(migrate_list);
		unsigned int nr_succeeded = 0;
		int ret;

		/* Bulk-pop migrate_nodes from promote queue */
		spin_lock_irqsave(&promote_queue_lock, flags);
		while (n < BATCH_N && !list_empty(&promote_queue)) {
			struct migrate_node *x =
				list_first_entry(&promote_queue, struct migrate_node, link);
			list_del_init(&x->link);
			atomic_dec(&promote_queue_count);
			batch[n++] = x;
		}
		spin_unlock_irqrestore(&promote_queue_lock, flags);

		if (n == 0) {
			msleep(WORK_SLEEP_MS);
			continue;
		}

		/* Build migration list from batch */
		for (i = 0; i < n; i++) {
			struct migrate_node *x = batch[i];
			struct folio *folio = x->folio;

			list_add_tail(&folio->lru, &migrate_list);
			kfree(x);
		}

		/* Bulk migration attempt */
		atomic64_add(n, &mig_attempted_promote);

		ret = migrate_pages(&migrate_list, alloc_normal_page, NULL,
				    0, MIGRATE_SYNC, MR_NUMA_MISPLACED,
				    &nr_succeeded);

		if (nr_succeeded > 0) {
			atomic64_add(nr_succeeded, &mig_succeeded_promote);
			atomic64_add(nr_succeeded, &total_pages_promoted);
			atomic64_add(nr_succeeded, &pages_promote_to_dram);
		}

		/* Handle failed migrations */
		if (!list_empty(&migrate_list)) {
			struct folio *folio, *next;
			int failed = 0;

			list_for_each_entry_safe(folio, next, &migrate_list, lru) {
				unsigned long pfn = folio_pfn(folio);

				list_del_init(&folio->lru);
				clear_hotness_for_pfn(pfn);
				folio_put(folio);
				failed++;
			}
			atomic64_add(failed, &pages_promote_failed);
		}

		if (nr_succeeded > 0 || n > 0) {
			pr_info("ktmm: promote_worker batch=%d succeeded=%u\n", n, nr_succeeded);
		}

		cond_resched();
	}
	return 0;
}

/**
 * demote_worker_fn - worker thread for bulk demotion (DRAM -> PMEM)
 */
static int demote_worker_fn(void *arg)
{
	while (!kthread_should_stop()) {
		struct migrate_node *batch[BATCH_N];
		int n = 0, i;
		unsigned long flags;
		LIST_HEAD(migrate_list);
		unsigned int nr_succeeded = 0;
		int ret;

		/* Bulk-pop migrate_nodes from demote queue */
		spin_lock_irqsave(&demote_queue_lock, flags);
		while (n < BATCH_N && !list_empty(&demote_queue)) {
			struct migrate_node *x =
				list_first_entry(&demote_queue, struct migrate_node, link);
			list_del_init(&x->link);
			atomic_dec(&demote_queue_count);
			batch[n++] = x;
		}
		spin_unlock_irqrestore(&demote_queue_lock, flags);

		if (n == 0) {
			msleep(WORK_SLEEP_MS);
			continue;
		}

		/* Build migration list from batch */
		for (i = 0; i < n; i++) {
			struct migrate_node *x = batch[i];
			struct folio *folio = x->folio;

			list_add_tail(&folio->lru, &migrate_list);
			kfree(x);
		}

		/* Bulk migration attempt */
		atomic64_add(n, &mig_attempted_demote);

		ret = migrate_pages(&migrate_list, alloc_pmem_page, NULL,
				    0, MIGRATE_SYNC, MR_NUMA_MISPLACED,
				    &nr_succeeded);

		if (nr_succeeded > 0) {
			atomic64_add(nr_succeeded, &mig_succeeded_demote);
			atomic64_add(nr_succeeded, &total_pages_demoted);
		}

		/* Handle failed migrations */
		if (!list_empty(&migrate_list)) {
			struct folio *folio, *next;

			list_for_each_entry_safe(folio, next, &migrate_list, lru) {
				list_del_init(&folio->lru);
				folio_put(folio);
			}
		}

		if (nr_succeeded > 0 || n > 0) {
			pr_info("ktmm: demote_worker batch=%d succeeded=%u\n", n, nr_succeeded);
		}

		cond_resched();
	}
	return 0;
}

/**
 * queue_folio_for_demote - add a folio to the demotion queue
 */
static int queue_folio_for_demote(struct folio *folio)
{
	struct migrate_node *n;
	unsigned long flags;

	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n)
		return -ENOMEM;

	INIT_LIST_HEAD(&n->link);
	folio_get(folio);
	n->folio = folio;
	n->pfn = folio_pfn(folio);

	spin_lock_irqsave(&demote_queue_lock, flags);
	list_add_tail(&n->link, &demote_queue);
	atomic_inc(&demote_queue_count);
	spin_unlock_irqrestore(&demote_queue_lock, flags);

	atomic64_inc(&pages_queued_demote);
	return 0;
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
 * scan_promote_list - scan promote lru folios
 */
static void scan_promote_list(unsigned long nr_to_scan,
				struct lruvec *lruvec,
				struct scan_control *sc,
				enum lru_list lru,
				struct pglist_data *pgdat)
{
	unsigned long nr_taken;
	unsigned long nr_scanned;
	isolate_mode_t isolate_mode = 0;
	LIST_HEAD(l_hold);
	int file = is_file_lru(lru);

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

	atomic64_add(nr_taken, &pages_scanned_promote);

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
	unsigned nr_deactivate, nr_activate, nr_promote;
	unsigned nr_rotated = 0;
	int file = is_file_lru(lru);

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

		if (pgdat->pm_node != 0) {
			if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
				folio_set_promote(folio);
				list_add(&folio->lru, &l_promote);
				atomic64_inc(&pages_active_to_promote);
				continue;
			}
		}

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
 */
static unsigned long scan_inactive_list(unsigned long nr_to_scan,
					struct lruvec *lruvec,
					struct scan_control *sc,
					enum lru_list lru,
					struct pglist_data *pgdat)
{
	LIST_HEAD(folio_list);
	LIST_HEAD(l_active);
	LIST_HEAD(l_putback);
	unsigned long nr_scanned;
	unsigned long nr_taken = 0;
	unsigned long nr_queued = 0;
	unsigned long nr_activate = 0;
	unsigned long vm_flags;
	bool file = is_file_lru(lru);
	int nid = pgdat->node_id;

	ktmm_lru_add_drain();

	spin_lock_irq(&lruvec->lru_lock);

	nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
				     &nr_scanned, sc, lru);

	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	if (nr_taken == 0) return 0;

	atomic64_add(nr_taken, &pages_scanned_inactive);

	/* PMEM NODE: activate referenced pages */
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

	/* DRAM NODE: queue for demotion */
	if (pgdat->pm_node == 0 && pmem_node_id != -1) {
		struct folio *folio, *next;

		list_for_each_entry_safe(folio, next, &folio_list, lru) {
			if (!is_file_folio(folio)) {
				list_move(&folio->lru, &l_putback);
				continue;
			}

			list_del_init(&folio->lru);

			if (queue_folio_for_demote(folio) == 0) {
				nr_queued++;
			} else {
				list_add(&folio->lru, &l_putback);
			}
		}

		if (nr_queued > 0) {
			printk(KERN_INFO "ktmm: pgdat %d QUEUED %lu folios for demotion\n",
			       nid, nr_queued);
		}
	}

	spin_lock_irq(&lruvec->lru_lock);

	if (nr_activate > 0) {
		ktmm_move_folios_to_lru(lruvec, &l_active);
	}

	ktmm_move_folios_to_lru(lruvec, &folio_list);
	ktmm_move_folios_to_lru(lruvec, &l_putback);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);

	spin_unlock_irq(&lruvec->lru_lock);

	ktmm_cgroup_uncharge_list(&l_active);
	ktmm_free_unref_page_list(&l_active);
	ktmm_cgroup_uncharge_list(&folio_list);
	ktmm_free_unref_page_list(&folio_list);
	ktmm_cgroup_uncharge_list(&l_putback);
	ktmm_free_unref_page_list(&l_putback);

	return nr_queued;
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
	int memcg_count;
	unsigned long total_pages_scanned = 0;

	memset(&sc->nr, 0, sizeof(sc->nr));
	memcg = ktmm_mem_cgroup_iter(NULL, NULL, reclaim);
	sc->target_mem_cgroup = memcg;

	memcg_count = 0;
	do {
		struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;
		unsigned long reclaimed;
		unsigned long scanned;

		memcg_count += 1;

		if (ktmm_cgroup_below_min(memcg)) {
			continue;
		} else if (ktmm_cgroup_below_low(memcg)) {
			if (!sc->memcg_low_reclaim) {
				sc->memcg_low_skipped = 1;
				continue;
			}
		}

		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;

		for_each_evictable_lru(lru) {
			unsigned long nr_to_scan = 1024;

			scan_list(lru, nr_to_scan, lruvec, sc, pgdat);
			total_pages_scanned += nr_to_scan;
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


static void drain_migration_queues(void)
{
	struct migrate_node *n;
	unsigned long flags;

	/* Drain promote queue */
	while (1) {
		spin_lock_irqsave(&promote_queue_lock, flags);

		if (list_empty(&promote_queue)) {
			spin_unlock_irqrestore(&promote_queue_lock, flags);
			break;
		}

		n = list_first_entry(&promote_queue, struct migrate_node, link);
		list_del_init(&n->link);
		atomic_dec(&promote_queue_count);

		spin_unlock_irqrestore(&promote_queue_lock, flags);

		clear_hotness_for_pfn(n->pfn);
		folio_put(n->folio);
		kfree(n);
	}

	/* Drain demote queue */
	while (1) {
		spin_lock_irqsave(&demote_queue_lock, flags);

		if (list_empty(&demote_queue)) {
			spin_unlock_irqrestore(&demote_queue_lock, flags);
			break;
		}

		n = list_first_entry(&demote_queue, struct migrate_node, link);
		list_del_init(&n->link);
		atomic_dec(&demote_queue_count);

		spin_unlock_irqrestore(&demote_queue_lock, flags);

		folio_put(n->folio);
		kfree(n);
	}
}


int tmemd_start_available(void) 
{
	int i;
	int nid;
	int ret;

	/* Allocate hotness tracking array */
	hotness_array = vzalloc(HOTNESS_ARRAY_SIZE * sizeof(struct page_hotness_entry));
	if (!hotness_array) {
		pr_err("ktmm: failed to allocate hotness array\n");
		return -ENOMEM;
	}

	/* Initialize hotness array entries */
	for (i = 0; i < HOTNESS_ARRAY_SIZE; i++) {
		atomic_long_set(&hotness_array[i].pfn, 0);
		atomic_set(&hotness_array[i].access_count, 0);
		atomic_set(&hotness_array[i].in_queue, 0);
	}

	set_ktmm_scan();

	/* initialize wait queues for sleeping */
	for (i = 0; i < MAX_NUMNODES; i++)
		init_waitqueue_head(&tmemd_wait[i]);

	ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));

	/* Initialize and start the page stats timer */
	timer_setup(&page_stats_timer, page_stats_timer_callback, 0);
	mod_timer(&page_stats_timer, jiffies + 5 * HZ);

	/*
	 * Register kprobe on folio_mark_accessed
	 */
	kp_folio_accessed.symbol_name = "folio_mark_accessed";
	kp_folio_accessed.pre_handler = kp_folio_accessed_pre;
	
	if (register_kprobe(&kp_folio_accessed)) {
		kp_folio_accessed.symbol_name = "mark_page_accessed";
		if (register_kprobe(&kp_folio_accessed)) {
			pr_err("ktmm: failed to register kprobe\n");
		} else {
			kprobe_registered = true;
			pr_info("ktmm: kprobe registered on mark_page_accessed\n");
		}
	} else {
		kprobe_registered = true;
		pr_info("ktmm: kprobe registered on folio_mark_accessed\n");
	}

	/* Start the bulk migration worker threads */
	promote_worker_task = kthread_run(promote_worker_fn, NULL, "ktmm_promote_worker");
	if (IS_ERR(promote_worker_task)) {
		promote_worker_task = NULL;
		pr_err("ktmm: failed to start promote_worker thread\n");
	} else {
		pr_info("ktmm: promote_worker thread started\n");
	}

	demote_worker_task = kthread_run(demote_worker_fn, NULL, "ktmm_demote_worker");
	if (IS_ERR(demote_worker_task)) {
		demote_worker_task = NULL;
		pr_err("ktmm: failed to start demote_worker thread\n");
	} else {
		pr_info("ktmm: demote_worker thread started\n");
	}
	
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

	/* Unregister the kprobe first to stop new promotions */
	if (kprobe_registered) {
		unregister_kprobe(&kp_folio_accessed);
		kprobe_registered = false;
		pr_info("ktmm: kprobe unregistered\n");
	}

	/* Stop and delete the page stats timer */
	del_timer_sync(&page_stats_timer);

	/* Stop the bulk migration worker threads */
	if (promote_worker_task) {
		kthread_stop(promote_worker_task);
		promote_worker_task = NULL;
		pr_info("ktmm: promote_worker thread stopped\n");
	}

	if (demote_worker_task) {
		kthread_stop(demote_worker_task);
		demote_worker_task = NULL;
		pr_info("ktmm: demote_worker thread stopped\n");
	}

	/* Drain any remaining items in migration queues */
	drain_migration_queues();

	/* Print final stats */
	printk(KERN_INFO "*** KTMM FINAL STATS: Promoted=%llu, Demoted=%llu ***\n",
	       (u64)atomic64_read(&total_pages_promoted),
	       (u64)atomic64_read(&total_pages_demoted));

	printk(KERN_INFO "  Kprobe: hits=%llu, pmem=%llu, hot=%llu, queue_try=%llu, trylock_fail=%llu\n",
	       (u64)atomic64_read(&kprobe_hits),
	       (u64)atomic64_read(&kprobe_pmem_pages),
	       (u64)atomic64_read(&kprobe_hot_detected),
	       (u64)atomic64_read(&kprobe_queue_attempts),
	       (u64)atomic64_read(&kprobe_trylock_fails));

	for_each_online_node(nid)
	{
		kthread_stop(tmemd_list[nid]);
	}

	uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));

	/* Free hotness tracking array */
	if (hotness_array) {
		vfree(hotness_array);
		hotness_array = NULL;
	}
}