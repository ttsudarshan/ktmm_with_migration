/*
 *  ktmm_vmscan.c
 *
 *  Page scanning and related functions.
 *
 *  Migration logic adapted from uts_migrate.c (kernel 5.14) for kernel 6.1
 *  ONLY migrates file-backed pages (skips anonymous pages)
 *
 *  KEY FIX v7: SYMMETRIC promotion/demotion for 1:1 ratio
 *
 *  DRAM (cold -> demote):
 *    - Unreferenced file page on inactive list -> DEMOTE to PMEM
 *
 *  PMEM (hot -> promote):
 *    - Referenced file page on inactive list -> PROMOTE to DRAM (KEY FIX!)
 *    - Referenced file page on active list -> PROMOTE to DRAM
 *
 *  Now both directions require only ONE access/non-access to trigger migration!
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
 
 static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
 
 /* Migration debug counters */
 static atomic64_t migrate_filter_anon = ATOMIC64_INIT(0);
 static atomic64_t migrate_filter_compound = ATOMIC64_INIT(0);
 static atomic64_t migrate_filter_no_mapping = ATOMIC64_INIT(0);
 static atomic64_t migrate_attempted = ATOMIC64_INIT(0);
 static atomic64_t migrate_success = ATOMIC64_INIT(0);
 static atomic64_t migrate_alloc_fail = ATOMIC64_INIT(0);
 
 /* Promotion/demotion candidate counters by source */
 static atomic64_t promote_from_inactive = ATOMIC64_INIT(0);
 static atomic64_t promote_from_active = ATOMIC64_INIT(0);
 static atomic64_t demote_from_inactive = ATOMIC64_INIT(0);
 
 static struct timer_list page_stats_timer;
 
 static void page_stats_timer_callback(struct timer_list *t)
 {
   u64 promoted = atomic64_read(&total_pages_promoted);
   u64 demoted = atomic64_read(&total_pages_demoted);
 
   u64 scanned_inactive = atomic64_read(&pages_scanned_inactive);
   u64 scanned_active = atomic64_read(&pages_scanned_active);
 
   u64 filter_anon = atomic64_read(&migrate_filter_anon);
   u64 filter_compound = atomic64_read(&migrate_filter_compound);
   u64 filter_no_mapping = atomic64_read(&migrate_filter_no_mapping);
   u64 mig_attempted = atomic64_read(&migrate_attempted);
   u64 mig_success = atomic64_read(&migrate_success);
   u64 alloc_fail = atomic64_read(&migrate_alloc_fail);
 
   u64 promo_inactive = atomic64_read(&promote_from_inactive);
   u64 promo_active = atomic64_read(&promote_from_active);
   u64 demo_inactive = atomic64_read(&demote_from_inactive);
 
   printk(KERN_INFO "*** KTMM PAGE STATS: Total Promoted: %llu, Total Demoted: %llu ***\n",
          promoted, demoted);
 
   printk(KERN_INFO "*** KTMM PAGE FLOW DEBUG ***\n");
   printk(KERN_INFO "  Scanned: inactive=%llu, active=%llu\n",
          scanned_inactive, scanned_active);
   printk(KERN_INFO "  Promote from: inactive=%llu, active=%llu (total candidates=%llu)\n",
          promo_inactive, promo_active, promo_inactive + promo_active);
   printk(KERN_INFO "  Demote from: inactive=%llu\n", demo_inactive);
 
   printk(KERN_INFO "*** KTMM MIGRATION DEBUG ***\n");
   printk(KERN_INFO "  Filtered: anon=%llu, compound=%llu, no_mapping=%llu\n",
          filter_anon, filter_compound, filter_no_mapping);
   printk(KERN_INFO "  Migrate: attempted=%llu, success=%llu, alloc_fail=%llu\n",
          mig_attempted, mig_success, alloc_fail);
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
  * MIGRATION FUNCTIONS - Adapted from uts_migrate.c for kernel 6.1
  *****************************************************************************/
 
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
 
 static void ktmm_free_migrate_page(struct page *page, unsigned long private)
 {
   __free_pages(page, 0);
 }
 
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
 
   list_for_each_entry_safe(folio, next, folio_list, lru) {
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
 
   ret = migrate_pages(&pagelist,
           ktmm_alloc_migrate_page,
           ktmm_free_migrate_page,
           (unsigned long)target_nid,
           MIGRATE_SYNC,
           MR_NUMA_MISPLACED,
           &nr_succeeded);
 
   atomic64_add(nr_succeeded, &migrate_success);
 
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
 
 static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
           nodemask_t *nodemask)
 {
   nodemask_t nodemask_test;
   int nid;
 
   nodes_clear(nodemask_test);
 
   if ((gfp_mask & __GFP_PMEM) != 0) {
     for_each_node_state(nid, N_MEMORY) {
       if (NODE_DATA(nid)->pm_node != 0)
         node_set(nid, nodemask_test);
     }
     nodemask = &nodemask_test;
   }
   else if (pmem_node_id != -1) {
     for_each_node_state(nid, N_MEMORY) {
       if (NODE_DATA(nid)->pm_node == 0)
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
  * LIST SCANNING FUNCTIONS - SYMMETRIC LOGIC FOR 1:1 RATIO
  *
  * DRAM (node 0, pm_node=0):
  *   - scan_inactive_list: DEMOTE unreferenced file pages to PMEM
  *   - scan_active_list: deactivate unreferenced pages (normal)
  *
  * PMEM (node 1, pm_node!=0):
  *   - scan_inactive_list: PROMOTE referenced file pages to DRAM
  *   - scan_active_list: PROMOTE referenced file pages to DRAM
  *****************************************************************************/
 
 static void scan_active_list(unsigned long nr_to_scan,
         struct lruvec *lruvec,
         struct scan_control *sc,
         enum lru_list lru,
         struct pglist_data *pgdat)
 {
   unsigned long nr_taken;
   unsigned long nr_scanned;
   unsigned long nr_migrated = 0;
   unsigned long vm_flags;
   LIST_HEAD(l_hold);
   LIST_HEAD(l_active);
   LIST_HEAD(l_inactive);
   LIST_HEAD(l_promote);
   __maybe_unused unsigned nr_deactivate, nr_activate;
   __maybe_unused unsigned nr_rotated = 0;
   int file = is_file_lru(lru);
   __maybe_unused int nid = pgdat->node_id;
   int is_pmem_node = (pgdat->pm_node != 0);
 
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
 
     /* PMEM NODE: Promote referenced file-backed pages to DRAM */
     if (is_pmem_node) {
       if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         if (is_file_backed_folio(folio)) {
           list_add(&folio->lru, &l_promote);
           atomic64_inc(&promote_from_active);
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
   }
 
   /* PMEM NODE: Migrate hot pages to DRAM */
   if (is_pmem_node && !list_empty(&l_promote)) {
     int target_node = 0;
 
     ktmm_migrate_folio_list(&l_promote, target_node, &nr_migrated);
 
     if (nr_migrated > 0) {
       __mod_node_page_state(pgdat, NR_PROMOTED, nr_migrated);
       atomic64_add(nr_migrated, &total_pages_promoted);
     }
   }
 
   spin_lock_irq(&lruvec->lru_lock);
 
   ktmm_move_folios_to_lru(lruvec, &l_active);
   ktmm_move_folios_to_lru(lruvec, &l_inactive);
 
   if (!list_empty(&l_promote))
     ktmm_move_folios_to_lru(lruvec, &l_promote);
 
   list_splice(&l_inactive, &l_active);
 
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
 
   spin_unlock_irq(&lruvec->lru_lock);
 
   ktmm_cgroup_uncharge_list(&l_active);
   ktmm_free_unref_page_list(&l_active);
 }
 
 
 static unsigned long scan_inactive_list(unsigned long nr_to_scan,
           struct lruvec *lruvec,
           struct scan_control *sc,
           enum lru_list lru,
           struct pglist_data *pgdat)
 {
   LIST_HEAD(folio_list);
   LIST_HEAD(l_demote);
   LIST_HEAD(l_promote);
   unsigned long nr_scanned;
   unsigned long nr_taken = 0;
   unsigned long nr_demoted = 0;
   unsigned long nr_promoted = 0;
   unsigned long vm_flags;
   bool file = is_file_lru(lru);
   __maybe_unused int nid = pgdat->node_id;
   int is_pmem_node = (pgdat->pm_node != 0);
   int is_dram_node = (pgdat->pm_node == 0);
 
   ktmm_lru_add_drain();
 
   spin_lock_irq(&lruvec->lru_lock);
 
   nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
              &nr_scanned, sc, lru);
 
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
 
   spin_unlock_irq(&lruvec->lru_lock);
 
   if (nr_taken == 0)
     return 0;
 
   atomic64_add(nr_taken, &pages_scanned_inactive);
 
   {
     struct folio *folio, *next;
 
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
       int is_referenced = ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags);
       int is_file = is_file_backed_folio(folio);
 
       /*
        * PMEM NODE: PROMOTE referenced file-backed pages to DRAM!
        * KEY FIX: Previously we just activated, now we promote directly!
        */
       if (is_pmem_node && is_referenced && is_file) {
         list_del(&folio->lru);
         list_add(&folio->lru, &l_promote);
         atomic64_inc(&promote_from_inactive);
         continue;
       }
 
       /* DRAM NODE: DEMOTE unreferenced file-backed pages to PMEM */
       if (is_dram_node && pmem_node_id != -1 && !is_referenced && is_file) {
         list_del(&folio->lru);
         list_add(&folio->lru, &l_demote);
         atomic64_inc(&demote_from_inactive);
         continue;
       }
     }
   }
 
   /* PMEM NODE: Promote hot file pages to DRAM */
   if (is_pmem_node && !list_empty(&l_promote)) {
     int target_node = 0;
 
     ktmm_migrate_folio_list(&l_promote, target_node, &nr_promoted);
 
     if (nr_promoted > 0) {
       __mod_node_page_state(pgdat, NR_PROMOTED, nr_promoted);
       atomic64_add(nr_promoted, &total_pages_promoted);
     }
   }
 
   /* DRAM NODE: Demote cold file pages to PMEM */
   if (is_dram_node && !list_empty(&l_demote)) {
     int target_node = pmem_node_id;
 
     ktmm_migrate_folio_list(&l_demote, target_node, &nr_demoted);
 
     if (nr_demoted > 0) {
       __mod_node_page_state(pgdat, NR_DEMOTED, nr_demoted);
       atomic64_add(nr_demoted, &total_pages_demoted);
     }
   }
   
   spin_lock_irq(&lruvec->lru_lock);
 
   if (!list_empty(&l_promote))
     ktmm_move_folios_to_lru(lruvec, &l_promote);
 
   if (!list_empty(&l_demote))
     ktmm_move_folios_to_lru(lruvec, &l_demote);
 
   ktmm_move_folios_to_lru(lruvec, &folio_list);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
 
   spin_unlock_irq(&lruvec->lru_lock);
 
   ktmm_cgroup_uncharge_list(&l_promote);
   ktmm_free_unref_page_list(&l_promote);
   ktmm_cgroup_uncharge_list(&l_demote);
   ktmm_free_unref_page_list(&l_demote);
   ktmm_cgroup_uncharge_list(&folio_list);
   ktmm_free_unref_page_list(&folio_list);
 
   return nr_demoted + nr_promoted;
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
 
   printk(KERN_INFO "*** KTMM FINAL: Promoted: %llu, Demoted: %llu ***\n",
          (u64)atomic64_read(&total_pages_promoted),
          (u64)atomic64_read(&total_pages_demoted));
 
   printk(KERN_INFO "*** KTMM Promote from: inactive=%llu, active=%llu ***\n",
          (u64)atomic64_read(&promote_from_inactive),
          (u64)atomic64_read(&promote_from_active));
 
   printk(KERN_INFO "*** KTMM Migration: attempted=%llu, success=%llu, alloc_fail=%llu ***\n",
          (u64)atomic64_read(&migrate_attempted),
          (u64)atomic64_read(&migrate_success),
          (u64)atomic64_read(&migrate_alloc_fail));
 
   for_each_online_node(nid)
   {
     kthread_stop(tmemd_list[nid]);
   }
 
   uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 }