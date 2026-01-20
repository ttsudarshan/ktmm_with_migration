/*
 * ktmm_vmscan.c
 *
 * Page scanning and related functions.
 * Updated for Linux Kernel 6.1
 * FIXED: 1:1 Ratio Stall (Force Promotion Success)
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
 
 // which node is the pmem node
 int pmem_node = -1;
 
 /* holds pointers to the tmemd daemons running per node */
 static struct task_struct *tmemd_list[MAX_NUMNODES];
 
 /* per node tmemd wait queues */
 wait_queue_head_t tmemd_wait[MAX_NUMNODES];
 
 /*****************************************************************************
  * Promotion/Demotion Balance & Stats
  *****************************************************************************/
 
 static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
 static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);
 
 /* Balance Counter for 1:1 Ratio Enforcement */
 static atomic64_t migration_balance = ATOMIC64_INIT(0);
 #define BALANCE_THRESHOLD 128 /* Tighter threshold to force 1:1 sooner */
 
 static atomic64_t pages_inactive_to_active = ATOMIC64_INIT(0);   
 static atomic64_t pages_active_to_inactive = ATOMIC64_INIT(0);   
 static atomic64_t pages_active_to_promote = ATOMIC64_INIT(0);    
 static atomic64_t pages_promote_to_dram = ATOMIC64_INIT(0);      
 static atomic64_t pages_promote_failed = ATOMIC64_INIT(0);       
 
 static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);
 
 static struct timer_list page_stats_timer;
 
 static void page_stats_timer_callback(struct timer_list *t)
 {
   u64 promoted = atomic64_read(&total_pages_promoted);
   u64 demoted = atomic64_read(&total_pages_demoted);
   s64 balance = atomic64_read(&migration_balance);
 
   u64 active_to_promote = atomic64_read(&pages_active_to_promote);
   u64 promote_to_dram = atomic64_read(&pages_promote_to_dram);
   u64 promote_failed = atomic64_read(&pages_promote_failed);
 
   printk(KERN_INFO "KTMM STATS: Promoted: %llu, Demoted: %llu (Balance: %lld)\n",
          promoted, demoted, balance);
   printk(KERN_INFO "KTMM FLOW: Act->Prom: %llu, Prom->DRAM: %llu, Fail: %llu\n",
          active_to_promote, promote_to_dram, promote_failed);
 
   mod_timer(&page_stats_timer, jiffies + 5 * HZ);
 }
 
 /************** HOOK WRAPPERS *****************************/
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
  */
 static struct page *ktmm_new_page_node(struct page *src, unsigned long private)
 {
   int nid = (int)private;
   /* * FIXED: Use GFP_KERNEL to allow reclaim/compaction if DRAM is full. 
    * This is critical for Promotion to succeed.
    */
   gfp_t gfp_mask = GFP_KERNEL | __GFP_HIGH | __GFP_MOVABLE | __GFP_THISNODE;
   struct page *newpage;
 
   newpage = alloc_pages_node(nid, gfp_mask, 0);
   return newpage;
 }
 
 static struct page *ktmm_alloc_pages(gfp_t gfp_mask, unsigned int order, int preferred_nid,
           nodemask_t *nodemask)
 {
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
   LIST_HEAD(l_hold);
   LIST_HEAD(l_migrate);
   int file = is_file_lru(lru);
 
   /* 1:1 Ratio Check - If we are ahead on promotion, wait. */
   if (atomic64_read(&migration_balance) > BALANCE_THRESHOLD) {
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
 
   /* Prepare list for migration */
   if (!list_empty(&l_hold)) {
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &l_hold, lru) {
       list_del(&folio->lru);
       list_add(&folio->lru, &l_migrate);
     }
   }
 
   /* Perform Batch Migration */
   if (!list_empty(&l_migrate)) {
     int target_nid = 0; /* Target DRAM */
     int ret;
 
     /* * FIXED: MIGRATE_SYNC forces dirty pages to write back. 
      * This prevents promotions from silently failing on dirty file pages.
      */
     ret = migrate_pages(&l_migrate, ktmm_new_page_node, NULL, 
             (unsigned long)target_nid, MIGRATE_SYNC, 
             MR_NUMA_MISPLACED, (unsigned int *)&nr_succeeded);
 
     if (nr_succeeded > 0) {
       __mod_node_page_state(pgdat, NR_PROMOTED, nr_succeeded);
       atomic64_add(nr_succeeded, &total_pages_promoted);
       atomic64_add(nr_succeeded, &pages_promote_to_dram);
       
       /* Adjust balance: Promotion increases positive balance */
       atomic64_add(nr_succeeded, &migration_balance);
     }
     
     /* Count failures and clean up */
     if (!list_empty(&l_migrate)) {
       unsigned long failed = 0;
       struct folio *f;
       list_for_each_entry(f, &l_migrate, lru) failed++;
       atomic64_add(failed, &pages_promote_failed);
       
       list_splice_init(&l_migrate, &l_hold);
     }
   }
 
   /* Put back any pages */
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
 
     folio = list_first_entry(&l_hold, struct folio, lru);
     list_del(&folio->lru);
 
     if (unlikely(!ktmm_folio_evictable(folio))) {
       ktmm_folio_putback_lru(folio);
       continue;
     }
 
     /* PMEM Node: Check for Hot Pages to Promote */
     if (pgdat->pm_node != 0) {
       if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         folio_set_promote(folio);
         list_add(&folio->lru, &l_promote);
         atomic64_inc(&pages_active_to_promote);
         continue;
       }
     }
 
     if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags) != 0) {
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
   LIST_HEAD(l_migrate);
   unsigned long nr_scanned;
   unsigned long nr_taken = 0;
   unsigned long nr_succeeded = 0;
   unsigned long nr_activate = 0;
   unsigned long vm_flags;
   bool file = is_file_lru(lru);
 
   /* 1:1 Ratio Check - If we are ahead on demotion, wait for promotion to catch up. */
   bool allow_demotion = true;
   if (atomic64_read(&migration_balance) < -BALANCE_THRESHOLD) {
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
 
   /* Check referenced bits */
   if (pgdat->pm_node != 0) {
     /* PMEM: Activate referenced pages (path to promotion) */
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
       cond_resched();
       if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         list_del(&folio->lru);
         folio_set_active(folio);
         list_add(&folio->lru, &l_active);
         nr_activate++;
         atomic64_inc(&pages_inactive_to_active);
       }
     }
   } else if (pgdat->pm_node == 0 && pmem_node_id != -1 && allow_demotion) {
     /* DRAM: Demote cold pages */
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
       cond_resched();
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
 
     /* Demotion is usually easier, but SYNC ensures we don't stall on dirty pages */
     ret = migrate_pages(&l_migrate, ktmm_new_page_node, NULL,
             (unsigned long)target_nid, MIGRATE_SYNC,
             MR_NUMA_MISPLACED, (unsigned int *)&nr_succeeded);
 
     if (nr_succeeded > 0) {
       __mod_node_page_state(pgdat, NR_DEMOTED, nr_succeeded);
       atomic64_add(nr_succeeded, &total_pages_demoted);
       /* Demotion makes balance negative */
       atomic64_sub(nr_succeeded, &migration_balance);
     }
     
     list_splice_init(&l_migrate, &folio_list);
   }
   
   spin_lock_irq(&lruvec->lru_lock);
 
   if (nr_activate > 0)
     ktmm_move_folios_to_lru(lruvec, &l_active);
 
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
 
     cond_resched();
 
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
 
   printk(KERN_INFO "KTMM FINAL: Promoted: %llu, Demoted: %llu\n",
          (u64)atomic64_read(&total_pages_promoted),
          (u64)atomic64_read(&total_pages_demoted));
 
   for_each_online_node(nid)
   {
     if (tmemd_list[nid])
       kthread_stop(tmemd_list[nid]);
   }
 
   uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 }