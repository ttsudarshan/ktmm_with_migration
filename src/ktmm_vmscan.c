/*
 * ktmm_vmscan.c
 *
 * Page scanning and related functions.
 * Implements Aggressive Bulk Migration for Kernel 6.1
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
 
 // Use GFP_NOIO to prevent filesystem deadlocks during migration allocation
 #define TMEMD_GFP_FLAGS GFP_NOIO
 
 int pmem_node = -1;
 
 /* holds pointers to the tmemd daemons running per node */
 static struct task_struct *tmemd_list[MAX_NUMNODES];
 
 /* per node tmemd wait queues */
 wait_queue_head_t tmemd_wait[MAX_NUMNODES];
 
 /*****************************************************************************
  * Bulk Migration Configuration
  *****************************************************************************/
 #define BATCH_N 32            /* Process 32 pages at a time */
 #define WORK_SLEEP_MS 100     /* Sleep when queue is empty */
 
 /*****************************************************************************
  * Bulk Migration Queue Structures
  *****************************************************************************/
 struct migrate_node {
   struct list_head link;
   struct folio *folio;
 };
 
 /* Promotion queue: PMEM -> DRAM (hot pages) */
 static LIST_HEAD(promote_queue);
 static DEFINE_SPINLOCK(promote_queue_lock);
 static atomic_t promote_queue_count = ATOMIC_INIT(0);
 
 /* Demotion queue: DRAM -> PMEM (cold pages) */
 static LIST_HEAD(demote_queue);
 static DEFINE_SPINLOCK(demote_queue_lock);
 static atomic_t demote_queue_count = ATOMIC_INIT(0);
 
 /* Worker threads */
 static struct task_struct *promote_worker_task;
 static struct task_struct *demote_worker_task;
 
 /*****************************************************************************
  * Statistics Counters
  *****************************************************************************/
 static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
 static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);
 
 /* Missing counters re-added here to fix compilation error */
 static atomic64_t pages_scanned_inactive = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_active = ATOMIC64_INIT(0);
 static atomic64_t pages_scanned_promote = ATOMIC64_INIT(0);
 
 static atomic64_t pages_queued_promote = ATOMIC64_INIT(0);
 static atomic64_t pages_queued_demote = ATOMIC64_INIT(0);
 
 static struct timer_list page_stats_timer;
 
 static void page_stats_timer_callback(struct timer_list *t)
 {
   u64 promoted = atomic64_read(&total_pages_promoted);
   u64 demoted = atomic64_read(&total_pages_demoted);
   u64 promote_q = atomic_read(&promote_queue_count);
   u64 demote_q = atomic_read(&demote_queue_count);
   u64 scan_in = atomic64_read(&pages_scanned_inactive);
   u64 q_dem = atomic64_read(&pages_queued_demote);
 
   printk(KERN_INFO "KTMM STATS: Promoted=%llu Demoted=%llu | Scanned(In)=%llu | QueueAttmpt(D)=%llu | Qs: P=%llu D=%llu\n",
          promoted, demoted, scan_in, q_dem, promote_q, demote_q);
 
   mod_timer(&page_stats_timer, jiffies + 5 * HZ);
 }
 
 /************** HOOK POINTERS *****************************/
 static struct mem_cgroup *(*pt_mem_cgroup_iter)(struct mem_cgroup *root,
         struct mem_cgroup *prev,
         struct mem_cgroup_reclaim_cookie *reclaim);
 static bool (*pt_zone_watermark_ok_safe)(struct zone *z, unsigned int order,
           unsigned long mark, int highest_zoneidx);
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
 
 
 /**************** KTMM IMPLEMENTATION **********************/
 static struct mem_cgroup *ktmm_mem_cgroup_iter(struct mem_cgroup *root, struct mem_cgroup *prev,
         struct mem_cgroup_reclaim_cookie *reclaim) {
   return pt_mem_cgroup_iter(root, prev, reclaim);
 }
 
 static bool ktmm_zone_watermark_ok_safe(struct zone *z, unsigned int order, unsigned long mark,
           int highest_zoneidx) {
   return pt_zone_watermark_ok_safe(z, order, mark, highest_zoneidx);
 }
 
 static struct pglist_data *ktmm_first_online_pgdat(void) {
   return pt_first_online_pgdat();
 }
 
 static struct zone *ktmm_next_zone(struct zone *zone) {
   return pt_next_zone(zone);
 }
 
 static void ktmm_free_unref_page_list(struct list_head *list) {
   return pt_free_unref_page_list(list);
 }
 
 static void ktmm_lru_add_drain(void) {
   pt_lru_add_drain();
 }
 
 static void ktmm_cgroup_update_lru_size(struct lruvec *lruvec, enum lru_list lru, int zid, int nr_pages) {
   pt_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
 }
 
 static void ktmm_cgroup_uncharge_list(struct list_head *page_list) {
   pt_cgroup_uncharge_list(page_list);
 }
 
 static unsigned long ktmm_isolate_lru_folios(unsigned long nr_to_scan, struct lruvec *lruvec,
           struct list_head *dst, unsigned long *nr_scanned,
           struct scan_control *sc, enum lru_list lru) {
   return pt_isolate_lru_folios(nr_to_scan, lruvec, dst, nr_scanned, sc, lru);
 }
 
 static unsigned int ktmm_move_folios_to_lru(struct lruvec *lruvec, struct list_head *list) {
   return pt_move_folios_to_lru(lruvec, list);
 }
 
 static void ktmm_folio_putback_lru(struct folio *folio) {
   pt_folio_putback_lru(folio);
 }
 
 static int ktmm_folio_referenced(struct folio *folio, int is_locked, struct mem_cgroup *memcg,
         unsigned long *vm_flags) {
   return pt_folio_referenced(folio, is_locked, memcg, vm_flags);
 }
 
 /*****************************************************************************
  * ALLOCATORS
  *****************************************************************************/
 
 struct page* alloc_pmem_page(struct  page *page, unsigned long data)
 {
     // Use GFP_NOIO to ensure migration doesn't wait on IO
   gfp_t gfp_mask = GFP_NOIO | __GFP_PMEM; 
   return alloc_page(gfp_mask);
 }
 
 struct page* alloc_normal_page(struct page *page, unsigned long data)
 {
     gfp_t gfp_mask = GFP_NOIO;
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
  * WORKER THREADS (Bulk Migration)
  *****************************************************************************/
 
 static int promote_worker_fn(void *arg)
 {
     // Important: PF_MEMALLOC prevents recursion deadlocks
     unsigned int pflags = current->flags;
     current->flags |= PF_MEMALLOC;
 
   while (!kthread_should_stop()) {
     struct migrate_node *batch[BATCH_N];
     int n = 0, i;
     unsigned long flags;
     LIST_HEAD(migrate_list);
     unsigned int nr_succeeded = 0;
     int ret;
 
         // 1. Consumer: Pop from queue
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
 
         // 2. Prepare migration list
     for (i = 0; i < n; i++) {
       struct migrate_node *x = batch[i];
       struct folio *folio = x->folio;
       list_add_tail(&folio->lru, &migrate_list);
       kfree(x);
     }
 
         // 3. Migrate (Kernel 6.1 compatible)
     ret = migrate_pages(&migrate_list, alloc_normal_page, NULL,
             0, MIGRATE_SYNC, MR_NUMA_MISPLACED,
             &nr_succeeded);
 
     if (nr_succeeded > 0) {
       atomic64_add(nr_succeeded, &total_pages_promoted);
     }
 
         // 4. Cleanup failed pages
     if (!list_empty(&migrate_list)) {
       struct folio *folio, *next;
       list_for_each_entry_safe(folio, next, &migrate_list, lru) {
         list_del_init(&folio->lru);
         folio_put(folio); // Release the reference taken during queuing
       }
     }
     cond_resched();
   }
 
     current->flags = pflags;
   return 0;
 }
 
 static int demote_worker_fn(void *arg)
 {
     unsigned int pflags = current->flags;
     current->flags |= PF_MEMALLOC;
 
   while (!kthread_should_stop()) {
     struct migrate_node *batch[BATCH_N];
     int n = 0, i;
     unsigned long flags;
     LIST_HEAD(migrate_list);
     unsigned int nr_succeeded = 0;
     int ret;
 
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
 
     for (i = 0; i < n; i++) {
       struct migrate_node *x = batch[i];
       struct folio *folio = x->folio;
       list_add_tail(&folio->lru, &migrate_list);
       kfree(x);
     }
 
     ret = migrate_pages(&migrate_list, alloc_pmem_page, NULL,
             0, MIGRATE_SYNC, MR_NUMA_MISPLACED,
             &nr_succeeded);
 
     if (nr_succeeded > 0) {
       atomic64_add(nr_succeeded, &total_pages_demoted);
     }
 
     if (!list_empty(&migrate_list)) {
       struct folio *folio, *next;
       list_for_each_entry_safe(folio, next, &migrate_list, lru) {
         list_del_init(&folio->lru);
         folio_put(folio);
       }
     }
     cond_resched();
   }
 
     current->flags = pflags;
   return 0;
 }
 
 // Queue Helper: Producer
 static int queue_folio_for_promote(struct folio *folio)
 {
   struct migrate_node *n;
   unsigned long flags;
 
   n = kmalloc(sizeof(*n), GFP_ATOMIC);
   if (!n) return -ENOMEM;
 
   INIT_LIST_HEAD(&n->link);
   folio_get(folio); // Take reference so page isn't freed while in queue
   n->folio = folio;
 
   spin_lock_irqsave(&promote_queue_lock, flags);
   list_add_tail(&n->link, &promote_queue);
   atomic_inc(&promote_queue_count);
   spin_unlock_irqrestore(&promote_queue_lock, flags);
     
     atomic64_inc(&pages_queued_promote);
   return 0;
 }
 
 static int queue_folio_for_demote(struct folio *folio)
 {
   struct migrate_node *n;
   unsigned long flags;
 
   n = kmalloc(sizeof(*n), GFP_ATOMIC);
   if (!n) return -ENOMEM;
 
   INIT_LIST_HEAD(&n->link);
   folio_get(folio);
   n->folio = folio;
 
   spin_lock_irqsave(&demote_queue_lock, flags);
   list_add_tail(&n->link, &demote_queue);
   atomic_inc(&demote_queue_count);
   spin_unlock_irqrestore(&demote_queue_lock, flags);
 
     atomic64_inc(&pages_queued_demote);
   return 0;
 }
 
 /*****************************************************************************
  * Scanning
  *****************************************************************************/
 
 /* Commented out unused functions to fix compiler warnings
 static bool ktmm_cgroup_below_low(struct mem_cgroup *memcg) {
   return READ_ONCE(memcg->memory.elow) >= page_counter_read(&memcg->memory);
 }
 
 static bool ktmm_cgroup_below_min(struct mem_cgroup *memcg) {
   return READ_ONCE(memcg->memory.emin) >= page_counter_read(&memcg->memory);
 }
 */
 
 static __always_inline void ktmm_update_lru_sizes(struct lruvec *lruvec,
       enum lru_list lru, unsigned long *nr_zone_taken) {
   int zid;
   for (zid = 0; zid < MAX_NR_ZONES; zid++) {
     if (!nr_zone_taken[zid]) continue;
     ktmm_cgroup_update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
   }
 }
 
 static inline bool ktmm_folio_evictable(struct folio *folio) {
   bool ret;
   rcu_read_lock();
   ret = !mapping_unevictable(folio_mapping(folio)) && !folio_test_mlocked(folio);
   rcu_read_unlock();
   return ret;
 }
 
 static inline bool ktmm_folio_needs_release(struct folio *folio) {
   struct address_space *mapping = folio_mapping(folio);
   return folio_has_private(folio) || (mapping && mapping_release_always(mapping));
 }
 
 static __always_inline bool is_file_folio(struct folio *folio)
 {
   if (folio_test_anon(folio)) return false;
   if (folio_test_hugetlb(folio) || folio_test_large(folio)) return false;
   if (!folio_mapping(folio)) return false;
   if (!folio_mapping(folio)->host) return false;
   return true;
 }
 
 // -----------------------------------------------------------
 // SCAN LISTS - Feeds the Queues
 // -----------------------------------------------------------
 
 static void scan_promote_list(unsigned long nr_to_scan, struct lruvec *lruvec,
         struct scan_control *sc, enum lru_list lru,
         struct pglist_data *pgdat)
 {
   unsigned long nr_taken;
   unsigned long nr_scanned;
   LIST_HEAD(l_hold);
   LIST_HEAD(l_putback);
   int file = is_file_lru(lru);
     // Removed unused variable 'nid' to fix compiler warning
   // int nid = pgdat->node_id;
 
   struct list_head *src = &lruvec->lists[lru];
   if (list_empty(src)) return;
 
   ktmm_lru_add_drain();
 
   spin_lock_irq(&lruvec->lru_lock);
   nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &l_hold,
           &nr_scanned, sc, lru);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
   spin_unlock_irq(&lruvec->lru_lock);
 
   atomic64_add(nr_taken, &pages_scanned_promote); 
 
   if (nr_taken > 0) {
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &l_hold, lru) {
       list_del_init(&folio->lru);
 
             // Add to queue
       if (queue_folio_for_promote(folio) != 0) {
         list_add(&folio->lru, &l_putback);
       }
     }
   }
     
   spin_lock_irq(&lruvec->lru_lock);
   ktmm_move_folios_to_lru(lruvec, &l_hold);
   ktmm_move_folios_to_lru(lruvec, &l_putback);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
   spin_unlock_irq(&lruvec->lru_lock);
 
   ktmm_cgroup_uncharge_list(&l_hold);
   ktmm_free_unref_page_list(&l_hold);
   ktmm_cgroup_uncharge_list(&l_putback);
   ktmm_free_unref_page_list(&l_putback);
 }
 
 
 static void scan_active_list(unsigned long nr_to_scan, struct lruvec *lruvec,
         struct scan_control *sc, enum lru_list lru,
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
 
     if (unlikely(!ktmm_folio_evictable(folio))) {
       ktmm_folio_putback_lru(folio);
       continue;
     }
 
     if (pgdat->pm_node != 0) {
       if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         folio_set_promote(folio);
         list_add(&folio->lru, &l_promote);
         continue;
       }
     }
 
     folio_clear_active(folio);
     folio_set_workingset(folio);
     list_add(&folio->lru, &l_inactive);
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
 
 static unsigned long scan_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec,
           struct scan_control *sc, enum lru_list lru,
           struct pglist_data *pgdat)
 {
   LIST_HEAD(folio_list);
   LIST_HEAD(l_active);
   LIST_HEAD(l_putback);
   unsigned long nr_scanned;
   unsigned long nr_taken = 0;
   unsigned long nr_activate = 0;
   unsigned long vm_flags;
   bool file = is_file_lru(lru);
 
   ktmm_lru_add_drain();
 
   spin_lock_irq(&lruvec->lru_lock);
   nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list,
              &nr_scanned, sc, lru);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
   spin_unlock_irq(&lruvec->lru_lock);
 
   if (nr_taken == 0) return 0;
 
   atomic64_add(nr_taken, &pages_scanned_inactive);
 
   if (pgdat->pm_node != 0) {
         // PMEM NODE: Check referenced to Promote
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
       if (ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         list_del(&folio->lru);
         folio_set_active(folio);
         list_add(&folio->lru, &l_active);
         nr_activate++;
       }
     }
   }
 
   if (pgdat->pm_node == 0 && pmem_node_id != -1) {
         // DRAM NODE: Aggressively Demote Everything
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
             
             // REMOVED CHECK: is_file_folio()
             // We now migrate anonymous pages too (heap/stack) to test the mechanism.
 
       list_del_init(&folio->lru);
             
             // Add to queue
       if (queue_folio_for_demote(folio) != 0) {
         list_add(&folio->lru, &l_putback);
       }
     }
   }
   
   spin_lock_irq(&lruvec->lru_lock);
   if (nr_activate > 0) ktmm_move_folios_to_lru(lruvec, &l_active);
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
 
   return 0;
 }
 
 static unsigned long scan_list(enum lru_list lru, unsigned long nr_to_scan,
         struct lruvec *lruvec, struct scan_control *sc,
         struct pglist_data *pgdat)
 {
   if (is_active_lru(lru)) scan_active_list(nr_to_scan, lruvec, sc, lru, pgdat);
   if(is_promote_lru(lru)) scan_promote_list(nr_to_scan, lruvec, sc, lru, pgdat);
   return scan_inactive_list(nr_to_scan, lruvec, sc, lru, pgdat);
 }
 
 static void scan_node(pg_data_t *pgdat, struct scan_control *sc,
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
 
         // Force scan regardless of memory pressure
     for_each_evictable_lru(lru) {
       unsigned long nr_to_scan = 1024; 
       scan_list(lru, nr_to_scan, lruvec, sc, pgdat);
     }
         
         cond_resched();
 
   } while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
 }
 
 
 /*****************************************************************************
  * Daemon Functions & Related
  *****************************************************************************/
 
 static void tmemd_try_to_sleep(pg_data_t *pgdat, int nid)
 {
   long remaining = 0;
   DEFINE_WAIT(wait);
 
   if (freezing(current) || kthread_should_stop()) return;
   
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
     folio_put(n->folio);
     kfree(n);
   }
 
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
 
   set_ktmm_scan();
 
   for (i = 0; i < MAX_NUMNODES; i++)
     init_waitqueue_head(&tmemd_wait[i]);
 
   ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 
   timer_setup(&page_stats_timer, page_stats_timer_callback, 0);
   mod_timer(&page_stats_timer, jiffies + 5 * HZ);
 
   promote_worker_task = kthread_run(promote_worker_fn, NULL, "ktmm_promote_worker");
   if (IS_ERR(promote_worker_task)) {
     promote_worker_task = NULL;
     pr_err("ktmm: failed to start promote_worker thread\n");
   }
 
   demote_worker_task = kthread_run(demote_worker_fn, NULL, "ktmm_demote_worker");
   if (IS_ERR(demote_worker_task)) {
     demote_worker_task = NULL;
     pr_err("ktmm: failed to start demote_worker thread\n");
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
 
   del_timer_sync(&page_stats_timer);
 
   if (promote_worker_task) {
     kthread_stop(promote_worker_task);
     promote_worker_task = NULL;
   }
 
   if (demote_worker_task) {
     kthread_stop(demote_worker_task);
     demote_worker_task = NULL;
   }
 
   drain_migration_queues();
 
   for_each_online_node(nid)
   {
     kthread_stop(tmemd_list[nid]);
   }
 
   uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 }