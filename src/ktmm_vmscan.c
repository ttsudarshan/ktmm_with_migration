/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 *
 *  Migration logic adapted EXACTLY from uts_migrate.c (kernel 5.14) for kernel 6.1
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
 
 static struct task_struct *tmemd_list[MAX_NUMNODES];
 wait_queue_head_t tmemd_wait[MAX_NUMNODES];
 
 
 /*****************************************************************************
  * Promotion/Demotion Page Counters
  *****************************************************************************/
 
 static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
 static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);
 
 /*****************************************************************************
  * Page Flow Debug Counters
  *****************************************************************************/
 
 static atomic64_t pages_inactive_to_active = ATOMIC64_INIT(0);
 static atomic64_t pages_active_to_inactive = ATOMIC64_INIT(0);
 static atomic64_t pages_active_to_promote = ATOMIC64_INIT(0);
 static atomic64_t pages_promote_to_dram = ATOMIC64_INIT(0);
 static atomic64_t pages_promote_failed = ATOMIC64_INIT(0);
 
 static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);
 
 /* Migration debug counters */
 static atomic64_t migrate_filter_anon = ATOMIC64_INIT(0);
 static atomic64_t migrate_filter_compound = ATOMIC64_INIT(0);
 static atomic64_t migrate_filter_no_mapping = ATOMIC64_INIT(0);
 static atomic64_t migrate_attempted = ATOMIC64_INIT(0);
 static atomic64_t migrate_success = ATOMIC64_INIT(0);
 
 static struct timer_list page_stats_timer;
 
 static void page_stats_timer_callback(struct timer_list *t)
 {
   u64 promoted = atomic64_read(&total_pages_promoted);
   u64 demoted = atomic64_read(&total_pages_demoted);
 
   u64 inactive_to_active = atomic64_read(&pages_inactive_to_active);
   u64 active_to_inactive = atomic64_read(&pages_active_to_inactive);
   u64 active_to_promote = atomic64_read(&pages_active_to_promote);
   u64 promote_to_dram = atomic64_read(&pages_promote_to_dram);
   u64 promote_failed = atomic64_read(&pages_promote_failed);
   u64 scanned_inactive = atomic64_read(&pages_scanned_inactive);
   u64 scanned_active = atomic64_read(&pages_scanned_active);
   u64 scanned_promote = atomic64_read(&pages_scanned_promote);
 
   u64 filter_anon = atomic64_read(&migrate_filter_anon);
   u64 filter_compound = atomic64_read(&migrate_filter_compound);
   u64 filter_no_mapping = atomic64_read(&migrate_filter_no_mapping);
   u64 mig_attempted = atomic64_read(&migrate_attempted);
   u64 mig_success = atomic64_read(&migrate_success);
 
   printk(KERN_INFO "*** KTMM PAGE STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
          promoted, demoted);
 
   printk(KERN_INFO "*** KTMM PAGE FLOW DEBUG ***\n");
   printk(KERN_INFO "  Scanned: inactive=%llu, active=%llu, promote=%llu\n",
          scanned_inactive, scanned_active, scanned_promote);
   printk(KERN_INFO "  Flow: inactive->active=%llu, active->inactive=%llu\n",
          inactive_to_active, active_to_inactive);
   printk(KERN_INFO "  Flow: active->promote=%llu, promote->DRAM=%llu (failed=%llu)\n",
          active_to_promote, promote_to_dram, promote_failed);
 
   printk(KERN_INFO "*** KTMM MIGRATION DEBUG ***\n");
   printk(KERN_INFO "  Filtered: anon=%llu, compound=%llu, no_mapping=%llu\n",
          filter_anon, filter_compound, filter_no_mapping);
   printk(KERN_INFO "  Migrate: attempted=%llu, success=%llu\n",
          mig_attempted, mig_success);
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
  * MIGRATION FUNCTIONS - EXACT copy of uts_migrate.c logic for kernel 6.1
  *
  * From uts_migrate.c:
  * - uts_alloc_migrate_page() allocates on target node with __GFP_THISNODE
  * - uts_free_migrate_page() frees failed allocation
  * - uts_migrate_one_file_page() handles single page migration
  * - uts_migrate_file_pages_bulk_vec() handles bulk migration
  *****************************************************************************/
 
 /**
  * ktmm_alloc_migrate_page - EXACT copy of uts_alloc_migrate_page
  *
  * From uts_migrate.c:
  *   newp = alloc_pages_node(nid, GFP_HIGHUSER_MOVABLE | __GFP_THISNODE, 0);
  */
 static struct page *ktmm_alloc_migrate_page(struct page *page, unsigned long private)
 {
   int nid = (int)private;
   struct page *newp;
 
   /* Allocate destination page on the target node - EXACT same as uts_migrate.c */
   newp = alloc_pages_node(nid, GFP_HIGHUSER_MOVABLE | __GFP_THISNODE, 0);
 
   return newp;
 }
 
 /**
  * ktmm_free_migrate_page - EXACT copy of uts_free_migrate_page
  */
 static void ktmm_free_migrate_page(struct page *page, unsigned long private)
 {
   __free_pages(page, 0);
 }
 
 /**
  * ktmm_migrate_folio_list - Migrate already-isolated folios
  *
  * This adapts uts_migrate_file_pages_bulk_vec() for KTMM's use case.
  *
  * KEY DIFFERENCE from uts_migrate.c:
  * - uts_migrate.c: caller provides extra ref, then isolate_lru_page() adds ref, then put_page()
  * - KTMM: folios already isolated by ktmm_isolate_lru_folios(), only have isolation ref
  *
  * So we do NOT call folio_put() - the folio only has the isolation reference.
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
    * Filter and build migration list.
    * EXACT same filters as uts_migrate.c:
    *   if (PageAnon(page) || PageCompound(page) || !page_mapping(page))
    *       continue;
    */
   list_for_each_entry_safe(folio, next, folio_list, lru) {
     /* Same quick filters as uts_migrate.c */
     if (folio_test_anon(folio)) {
       atomic64_inc(&migrate_filter_anon);
       continue;
     }
 
     if (folio_test_large(folio)) {
       atomic64_inc(&migrate_filter_compound);
       continue;
     }
 
     if (!folio_mapping(folio)) {
       atomic64_inc(&migrate_filter_no_mapping);
       continue;
     }
 
     /*
      * CRITICAL DIFFERENCE FROM uts_migrate.c:
      *
      * uts_migrate.c does:
      *   r = isolate_lru_page(page);  // adds ref
      *   put_page(page);              // drops caller's extra ref
      *   list_add_tail(&page->lru, &plist);
      *   pages[i] = NULL;
      *
      * But our folios are ALREADY isolated by ktmm_isolate_lru_folios().
      * They only have the isolation reference, NO extra caller ref.
      * So we must NOT call folio_put() here!
      *
      * Just move to migration list.
      */
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
 
   /*
    * Call migrate_pages() - EXACT same as uts_migrate.c except kernel 6.1 has 7 args.
    *
    * uts_migrate.c (kernel 5.14):
    *   ret = migrate_pages(&plist, uts_alloc_migrate_page, uts_free_migrate_page,
    *                       (unsigned long)target_nid, MIGRATE_SYNC, MR_NUMA_MISPLACED);
    *
    * kernel 6.1 adds: unsigned int *ret_succeeded
    */
   ret = migrate_pages(&pagelist,
           ktmm_alloc_migrate_page,
           ktmm_free_migrate_page,
           (unsigned long)target_nid,
           MIGRATE_SYNC,
           MR_NUMA_MISPLACED,
           &nr_succeeded);
 
   atomic64_add(nr_succeeded, &migrate_success);
 
   /*
    * Any leftovers failed: put them back - EXACT same as uts_migrate.c:
    *   list_for_each_entry_safe(p, n, &plist, lru) {
    *       list_del_init(&p->lru);
    *       putback_lru_page(p);
    *   }
    */
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
  * ALLOC & SWAP - FIXED nodemask initialization bug!
  *****************************************************************************/
 
 struct page* alloc_pmem_page(struct page *page, unsigned long data)
 {
   gfp_t gfp_mask = GFP_USER | __GFP_PMEM;
   return alloc_page(gfp_mask);
 }
 
 struct page* alloc_normal_page(struct page *page, unsigned long data)
 {
   gfp_t gfp_mask = GFP_USER;
   return alloc_page(gfp_mask);
 }
 
 /**
  * ktmm_alloc_pages - hooked __alloc_pages
  *
  * CRITICAL FIX: Initialize nodemask_test before using it!
  * The original code had uninitialized nodemask_test causing nodemask=0 failures.
  */
 static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
           nodemask_t *nodemask)
 {
   nodemask_t nodemask_test;
   int nid;
 
   /*
    * CRITICAL FIX: Initialize nodemask to empty first!
    * Without this, nodemask_test contains garbage and node_set/node_clear
    * produce garbage results, causing allocation failures with nodemask=0.
    */
   nodes_clear(nodemask_test);
 
   if ((gfp_mask & __GFP_PMEM) != 0) {
     /* Requesting PMEM: set only PMEM nodes */
     for_each_node_state(nid, N_MEMORY) {
       if (NODE_DATA(nid)->pm_node != 0)
         node_set(nid, nodemask_test);
     }
     nodemask = &nodemask_test;
   }
   else if ((gfp_mask & __GFP_PMEM) == 0 && pmem_node_id != -1) {
     /*
      * NOT requesting PMEM and PMEM exists: set only DRAM nodes.
      *
      * BUT: If __GFP_THISNODE is set, the caller explicitly wants
      * a specific node. Don't interfere with migration allocations!
      */
     if (gfp_mask & __GFP_THISNODE) {
       /* Don't modify nodemask for explicit node requests (migration) */
       return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);
     }
 
     for_each_node_state(nid, N_MEMORY) {
       if (NODE_DATA(nid)->pm_node == 0)
         node_set(nid, nodemask_test);
     }
     nodemask = &nodemask_test;
   }
 
   return pt_alloc_pages(gfp_mask, order, preferred_nid, nodemask);
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
 
 
 /*****************************************************************************
  * LIST SCANNING FUNCTIONS
  *****************************************************************************/
 
 /**
  * scan_promote_list - scan promote lru folios for migration to DRAM
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
   LIST_HEAD(l_hold);
   int file = is_file_lru(lru);
   __maybe_unused int nid = pgdat->node_id;
   int target_node = 0;  /* DRAM node */
 
   struct list_head *src = &lruvec->lists[lru];
 
   if (list_empty(src))
     return;
 
   ktmm_lru_add_drain();
 
   spin_lock_irq(&lruvec->lru_lock);
 
   nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
           &nr_scanned, sc, lru);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
 
   spin_unlock_irq(&lruvec->lru_lock);
 
   atomic64_add(nr_taken, &pages_scanned_promote);
 
   if (nr_taken == 0)
     goto done;
 
   /* PROMOTION: PMEM -> DRAM migration */
   ktmm_migrate_folio_list(&l_hold, target_node, &nr_migrated);
 
   if (nr_migrated > 0) {
     __mod_node_page_state(pgdat, NR_PROMOTED, nr_migrated);
     atomic64_add(nr_migrated, &total_pages_promoted);
     atomic64_add(nr_migrated, &pages_promote_to_dram);
     printk(KERN_INFO "KTMM: Promoted %lu pages from PMEM to DRAM\n", nr_migrated);
   }
 
 done:
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
    * DEMOTION: DRAM -> PMEM
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