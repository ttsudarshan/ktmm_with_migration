/*
 * ktmm_vmscan.c
 *
 * HYBRID IMPLEMENTATION:
 * 1. Promotion: Uses Kprobes + Access Counting (Exact "Working" Approach)
 * 2. Demotion: Uses LRU Scanning (Your Original Logic)
 * * Adapted for Kernel 6.1
 */

 #include <linux/module.h>
 #include <linux/kernel.h>
 #include <linux/init.h>
 #include <linux/kprobes.h>
 #include <linux/mm.h>
 #include <linux/page_ext.h>
 #include <linux/huge_mm.h>
 #include <linux/list.h>
 #include <linux/spinlock.h>
 #include <linux/slab.h>
 #include <linux/kthread.h>
 #include <linux/delay.h>
 #include <linux/sched.h>
 #include <linux/atomic.h>
 #include <linux/migrate.h>
 #include <linux/migrate_mode.h>
 #include <linux/node.h>
 #include <linux/psi.h>
 #include "ktmm_hook.h"
 #include "ktmm_vmscan.h"
 
 /*****************************************************************************
  * CONFIGURATION
  *****************************************************************************/
 #define HIGHEST_LEVEL 7        /* Promotion Threshold (from working code) */
 #define BATCH_N 32             /* Batch size for promotion */
 #define WORK_SLEEP_MS 10       /* Worker sleep time */
 #define TMEMD_GFP_FLAGS GFP_NOIO
 
 int pmem_node = -1;
 
 /* Statistics */
 static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
 static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);
 static atomic64_t promote_queued = ATOMIC64_INIT(0);
 static atomic64_t promote_failed = ATOMIC64_INIT(0);
 
 /* Demotion Scanner Threads */
 static struct task_struct *tmemd_list[MAX_NUMNODES];
 wait_queue_head_t tmemd_wait[MAX_NUMNODES];
 
 /*****************************************************************************
  * PROMOTION LOGIC (The "Working" Kprobe Approach)
  *****************************************************************************/
 
 struct promote_node {
   struct list_head link;
   struct page *page;
 };
 
 static LIST_HEAD(promote_list);
 static DEFINE_SPINLOCK(promote_lock);
 static atomic_t promote_count = ATOMIC_INIT(0);
 static struct task_struct *promote_worker_task;
 static struct kprobe kp;
 
 /* Fake struct for compilation if uts_slot_id is missing in standard kernels.
  * If your kernel has the patch, delete this struct definition. */
 struct ktmm_page_ext_stub {
     unsigned long uts_slot_id;
 };
 
 /* Helper to get page extension. Safely falls back if strict type isn't found */
 static inline unsigned long *get_uts_slot(struct page *page) {
     struct page_ext *pe = lookup_page_ext(page);
     if (!pe) return NULL;
     /* We assume the custom field is at the start or cast it. 
        Adjust this if you have the real struct definition! */
     return (unsigned long *)pe; 
 }
 
 static struct page *ktmm_new_page_node(struct page *src, unsigned long private)
 {
   int nid = (int)private;
   gfp_t gfp_mask = GFP_KERNEL | __GFP_HIGH | __GFP_MOVABLE | __GFP_THISNODE;
   return alloc_pages_node(nid, gfp_mask, 0);
 }
 
 /* * KPROBE HANDLER 
  * Intercepts folio_mark_accessed to count accesses.
  */
 static int kp_pre(struct kprobe *p, struct pt_regs *regs)
 {
   struct folio *folio;
   struct page *page;
   unsigned long *slot_ptr;
   unsigned long slot;
   struct promote_node *n;
   unsigned long flags;
 
   /* Kernel 6.1: Argument 1 is struct folio* */
   folio = (struct folio *)regs->di;
   if (!folio) return 0;
 
   /* Filter: Only File Pages, No Huge, No Anon */
   if (folio_test_anon(folio)) return 0;
   if (folio_test_large(folio)) return 0;
   if (!folio_mapping(folio)) return 0;
 
   page = &folio->page;
 
   /* * ACCESS COUNTING (The "Secret Sauce") * */
   slot_ptr = get_uts_slot(page);
   if (!slot_ptr) return 0;
 
   slot = READ_ONCE(*slot_ptr);
   
   /* Increment Counter */
   if (slot < HIGHEST_LEVEL) {
     WRITE_ONCE(*slot_ptr, slot + 1);
     return 0; /* Not hot enough yet */
   }
 
   /* Reset counter to avoid immediate re-queueing */
   WRITE_ONCE(*slot_ptr, 0);
 
   /* * QUEUE FOR PROMOTION * */
   n = kmalloc(sizeof(*n), GFP_ATOMIC);
   if (!n) return 0;
   
   INIT_LIST_HEAD(&n->link);
   get_page(page); /* Pin the page */
   n->page = page;
 
   spin_lock_irqsave(&promote_lock, flags);
   list_add_tail(&n->link, &promote_list);
   atomic_inc(&promote_count);
   spin_unlock_irqrestore(&promote_lock, flags);
   
   atomic64_inc(&promote_queued);
 
   return 0;
 }
 
 /*
  * PROMOTION WORKER THREAD
  * Wakes up, batches pages, and moves them to DRAM.
  */
 static int promote_worker_fn(void *arg)
 {
   while (!kthread_should_stop()) {
     struct promote_node *batch[BATCH_N];
     int n = 0, i;
     unsigned long flags;
     LIST_HEAD(migrate_list);
 
     /* 1. Drain the Queue */
     spin_lock_irqsave(&promote_lock, flags);
     while (n < BATCH_N && !list_empty(&promote_list)) {
       struct promote_node *x = list_first_entry(&promote_list, struct promote_node, link);
       list_del(&x->link);
       atomic_dec(&promote_count);
       batch[n++] = x;
     }
     spin_unlock_irqrestore(&promote_lock, flags);
 
     if (n == 0) {
       msleep(WORK_SLEEP_MS);
       continue;
     }
 
     /* 2. Build Migration List */
     for (i = 0; i < n; i++) {
       struct promote_node *x = batch[i];
       struct page *page = x->page;
       /* Only move if not already on DRAM (Node 0) */
       if (page_to_nid(page) != 0) {
         list_add(&page->lru, &migrate_list);
       } else {
         put_page(page); /* Already on DRAM */
       }
       kfree(x);
     }
 
     /* 3. Execute Batch Migration */
     if (!list_empty(&migrate_list)) {
       int nr_succeeded = 0;
       /* Target Node 0 (DRAM) */
       migrate_pages(&migrate_list, ktmm_new_page_node, NULL, 
               0, MIGRATE_SYNC, MR_NUMA_MISPLACED, &nr_succeeded);
       
       if (nr_succeeded > 0)
         atomic64_add(nr_succeeded, &total_pages_promoted);
       
       /* Clean up failures */
       if (!list_empty(&migrate_list)) {
         struct page *p, *tmp;
         list_for_each_entry_safe(p, tmp, &migrate_list, lru) {
           list_del(&p->lru);
           put_page(p);
           atomic64_inc(&promote_failed);
         }
       }
     }
     cond_resched();
   }
   return 0;
 }
 
 /*****************************************************************************
  * DEMOTION LOGIC (Your Original Scanner - Scaled Down)
  *****************************************************************************/
 
 /* Hooks wrappers needed for scanner */
 static struct mem_cgroup *(*pt_mem_cgroup_iter)(struct mem_cgroup *, struct mem_cgroup *, struct mem_cgroup_reclaim_cookie *);
 static struct pglist_data *(*pt_first_online_pgdat)(void);
 static void (*pt_lru_add_drain)(void);
 static unsigned long (*pt_isolate_lru_folios)(unsigned long, struct lruvec *, struct list_head *, unsigned long *, struct scan_control *, enum lru_list);
 static unsigned int (*pt_move_folios_to_lru)(struct lruvec *, struct list_head *);
 static void (*pt_cgroup_uncharge_list)(struct list_head *);
 static void (*pt_free_unref_page_list)(struct list_head *);
 static int (*pt_folio_referenced)(struct folio *, int, struct mem_cgroup *, unsigned long *);
 static struct page *(*pt_alloc_pages)(gfp_t, unsigned int, int, nodemask_t *);
 
 /* Wrappers */
 static struct mem_cgroup *ktmm_mem_cgroup_iter(struct mem_cgroup *r, struct mem_cgroup *p, struct mem_cgroup_reclaim_cookie *c) { return pt_mem_cgroup_iter(r, p, c); }
 static struct pglist_data *ktmm_first_online_pgdat(void) { return pt_first_online_pgdat(); }
 static void ktmm_lru_add_drain(void) { pt_lru_add_drain(); }
 static unsigned long ktmm_isolate_lru_folios(unsigned long n, struct lruvec *v, struct list_head *d, unsigned long *s, struct scan_control *c, enum lru_list l) { return pt_isolate_lru_folios(n, v, d, s, c, l); }
 static unsigned int ktmm_move_folios_to_lru(struct lruvec *v, struct list_head *l) { return pt_move_folios_to_lru(v, l); }
 static void ktmm_cgroup_uncharge_list(struct list_head *l) { pt_cgroup_uncharge_list(l); }
 static void ktmm_free_unref_page_list(struct list_head *l) { pt_free_unref_page_list(l); }
 static int ktmm_folio_referenced(struct folio *f, int l, struct mem_cgroup *m, unsigned long *fl) { return pt_folio_referenced(f, l, m, fl); }
 static struct page *ktmm_alloc_pages(gfp_t g, unsigned int o, int p, nodemask_t *n) { return pt_alloc_pages(g, o, p, n); }
 
 /*
  * Scan Inactive List - ONLY Handles Demotion (DRAM -> PMEM)
  * We removed the promotion logic from here because the Kprobe handles it now.
  */
 static unsigned long scan_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec, struct scan_control *sc, enum lru_list lru, struct pglist_data *pgdat)
 {
   LIST_HEAD(folio_list);
   LIST_HEAD(l_migrate);
   unsigned long nr_scanned, nr_taken, nr_succeeded = 0;
   unsigned long vm_flags;
   int file = is_file_lru(lru);
 
   /* Only scan if we are on DRAM (Node 0) and PMEM exists */
   if (pgdat->node_id != 0 || pmem_node_id == -1) return 0;
 
   ktmm_lru_add_drain();
   spin_lock_irq(&lruvec->lru_lock);
   nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list, &nr_scanned, sc, lru);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
   spin_unlock_irq(&lruvec->lru_lock);
 
   if (nr_taken == 0) return 0;
 
   /* Find Cold Pages */
   if (!list_empty(&folio_list)) {
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
       /* If NOT referenced, queue for Demotion */
       if (!ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         list_del(&folio->lru);
         list_add(&folio->lru, &l_migrate);
       }
     }
   }
 
   /* Demote */
   if (!list_empty(&l_migrate)) {
     int target_nid = pmem_node_id;
     /* Sync Light is fine for demotion */
     migrate_pages(&l_migrate, ktmm_new_page_node, NULL, 
             (unsigned long)target_nid, MIGRATE_SYNC_LIGHT, 
             MR_NUMA_MISPLACED, &nr_succeeded);
     
     if (nr_succeeded > 0)
       atomic64_add(nr_succeeded, &total_pages_demoted);
     
     /* Failures put back */
     list_splice_init(&l_migrate, &folio_list);
   }
 
   spin_lock_irq(&lruvec->lru_lock);
   ktmm_move_folios_to_lru(lruvec, &folio_list);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, -nr_taken);
   spin_unlock_irq(&lruvec->lru_lock);
 
   ktmm_cgroup_uncharge_list(&folio_list);
   ktmm_free_unref_page_list(&folio_list);
   
   return nr_succeeded;
 }
 
 static void scan_node(pg_data_t *pgdat, struct scan_control *sc, struct mem_cgroup_reclaim_cookie *reclaim)
 {
   enum lru_list lru;
   struct mem_cgroup *memcg = ktmm_mem_cgroup_iter(NULL, NULL, reclaim);
   sc->target_mem_cgroup = memcg;
   int nid = pgdat->node_id;
 
   do {
     struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;
     cond_resched();
     /* Only scan Inactive File/Anon lists for demotion */
     scan_inactive_list(128, lruvec, sc, LRU_INACTIVE_FILE, pgdat);
     scan_inactive_list(128, lruvec, sc, LRU_INACTIVE_ANON, pgdat);
   } while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
 }
 
 static int demote_scanner_fn(void *p) 
 {
   pg_data_t *pgdat = (pg_data_t *)p;
   int nid = pgdat->node_id;
   struct mem_cgroup_reclaim_cookie reclaim = { .pgdat = pgdat };
   struct scan_control sc = { .nr_to_reclaim = SWAP_CLUSTER_MAX, .may_unmap = 1, .may_swap = 1 };
   struct task_struct *task = current;
   
   task->flags |= PF_MEMALLOC | PF_KSWAPD;
 
   while (!kthread_should_stop()) {
     /* Only run scanner on Node 0 (DRAM) */
     if (nid == 0) {
       scan_node(pgdat, &sc, &reclaim);
     }
     
     /* Sleep 2 seconds */
     if (kthread_should_stop()) break;
     schedule_timeout_interruptible(2 * HZ);
   }
 
   task->flags &= ~(PF_MEMALLOC | PF_KSWAPD);
   return 0;
 }
 
 /*****************************************************************************
  * INIT / EXIT
  *****************************************************************************/
 
 static struct ktmm_hook vmscan_hooks[] = {
   HOOK("mem_cgroup_iter", ktmm_mem_cgroup_iter, &pt_mem_cgroup_iter),
   HOOK("first_online_pgdat", ktmm_first_online_pgdat, &pt_first_online_pgdat),
   HOOK("free_unref_page_list", ktmm_free_unref_page_list, &pt_free_unref_page_list),
   HOOK("lru_add_drain", ktmm_lru_add_drain, &pt_lru_add_drain),
   HOOK("__mem_cgroup_uncharge_list", ktmm_cgroup_uncharge_list, &pt_cgroup_uncharge_list),
   HOOK("isolate_lru_folios", ktmm_isolate_lru_folios, &pt_isolate_lru_folios),
   HOOK("move_folios_to_lru", ktmm_move_folios_to_lru, &pt_move_folios_to_lru),
   HOOK("folio_referenced", ktmm_folio_referenced, &pt_folio_referenced),
   HOOK("__alloc_pages", ktmm_alloc_pages, &pt_alloc_pages),
 };
 
 static void print_stats(struct timer_list *t) {
   printk(KERN_INFO "KTMM STATS: Promoted (Kprobe): %llu | Demoted (Scan): %llu | Queued: %llu\n",
          (u64)atomic64_read(&total_pages_promoted), 
          (u64)atomic64_read(&total_pages_demoted),
          (u64)atomic64_read(&promote_queued));
 }
 static DEFINE_TIMER(stats_timer, print_stats);
 
 int tmemd_start_available(void) 
 {
   int nid, ret;
   
   set_ktmm_scan();
   ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 
   /* 1. Register Kprobe for Promotion */
   kp.symbol_name = "folio_mark_accessed";
   kp.pre_handler = kp_pre;
   if (register_kprobe(&kp)) {
     pr_err("KTMM: Failed to register kprobe\n");
     return -1;
   }
 
   /* 2. Start Promotion Worker */
   promote_worker_task = kthread_run(promote_worker_fn, NULL, "ktmm_promote");
   
   /* 3. Start Demotion Scanners */
   for_each_online_node(nid) {
     pg_data_t *pgdat = NODE_DATA(nid);
     if (nid == 1) {
       set_pmem_node_id(nid);
       set_pmem_node(nid);
     }
     tmemd_list[nid] = kthread_run(demote_scanner_fn, pgdat, "ktmm_demote");
   }
 
   mod_timer(&stats_timer, jiffies + 5 * HZ);
   return ret;
 }
 
 void tmemd_stop_all(void)
 {
   int nid;
   del_timer_sync(&stats_timer);
   unregister_kprobe(&kp);
   
   if (promote_worker_task) kthread_stop(promote_worker_task);
 
   for_each_online_node(nid) {
     if (tmemd_list[nid]) kthread_stop(tmemd_list[nid]);
   }
   uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 }