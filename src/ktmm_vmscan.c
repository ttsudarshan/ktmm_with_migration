/*
 * ktmm_vmscan.c
 *
 * HYBRID IMPLEMENTATION:
 * 1. Promotion: Kprobes + Hash Table + Dynamic Symbol Lookup (Backdoor Method)
 * 2. Demotion: Aggressive LRU Scanning
 * * Fixed for Kernel 6.1 (Solves modpost & implicit declaration errors)
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
 #include <linux/hashtable.h>
 #include "ktmm_hook.h"
 #include "ktmm_vmscan.h"
 
 /*****************************************************************************
  * CONFIGURATION
  *****************************************************************************/
 #define HIGHEST_LEVEL 7        
 #define BATCH_N 32             
 #define WORK_SLEEP_MS 10       
 
 int pmem_node = -1;
 
 /* Statistics */
 static atomic64_t total_pages_promoted = ATOMIC64_INIT(0);
 static atomic64_t total_pages_demoted = ATOMIC64_INIT(0);
 static atomic64_t promote_queued = ATOMIC64_INIT(0);
 static atomic64_t promote_failed = ATOMIC64_INIT(0);
 
 static struct task_struct *tmemd_list[MAX_NUMNODES];
 wait_queue_head_t tmemd_wait[MAX_NUMNODES];
 
 /*****************************************************************************
  * DYNAMIC SYMBOL LOOKUP (The "Backdoor" Fix)
  *****************************************************************************/
 typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
 static kallsyms_lookup_name_t kallsyms_lookup_name_ptr = NULL;
 
 /* Internal function pointers */
 typedef int (*folio_isolate_lru_func_t)(struct folio *folio);
 typedef void (*folio_putback_lru_func_t)(struct folio *folio);
 
 static folio_isolate_lru_func_t kernel_folio_isolate_lru = NULL;
 static folio_putback_lru_func_t kernel_folio_putback_lru = NULL;
 
 /* * TRICK: Register a kprobe on 'kallsyms_lookup_name' to get its address,
  * because the symbol itself is not exported in Kernel 6.1+.
  */
 static struct kprobe kp_lookup = {
     .symbol_name = "kallsyms_lookup_name",
 };
 
 static int resolve_kallsyms(void)
 {
     int ret = register_kprobe(&kp_lookup);
     if (ret < 0) {
         pr_err("KTMM: Failed to probe kallsyms_lookup_name, ret=%d\n", ret);
         return ret;
     }
     
     kallsyms_lookup_name_ptr = (kallsyms_lookup_name_t)kp_lookup.addr;
     unregister_kprobe(&kp_lookup);
     
     if (!kallsyms_lookup_name_ptr) {
         pr_err("KTMM: Could not retrieve kallsyms_lookup_name address\n");
         return -EFAULT;
     }
     
     pr_info("KTMM: kallsyms_lookup_name found at %px\n", kallsyms_lookup_name_ptr);
     return 0;
 }
 
 static int lookup_internal_functions(void)
 {
     unsigned long isolate_addr, putback_addr;
 
     if (resolve_kallsyms() < 0) return -1;
 
     isolate_addr = kallsyms_lookup_name_ptr("folio_isolate_lru");
     putback_addr = kallsyms_lookup_name_ptr("folio_putback_lru");
 
     /* Fallback for older/alternate names */
     if (!isolate_addr) isolate_addr = kallsyms_lookup_name_ptr("isolate_lru_page");
     if (!putback_addr) putback_addr = kallsyms_lookup_name_ptr("putback_lru_page");
     
     if (isolate_addr && putback_addr) {
         kernel_folio_isolate_lru = (folio_isolate_lru_func_t)isolate_addr;
         kernel_folio_putback_lru = (folio_putback_lru_func_t)putback_addr;
         pr_info("KTMM: Symbols found. Isolate: %lx, Putback: %lx\n", isolate_addr, putback_addr);
         return 0;
     }
     
     pr_err("KTMM: Failed to lookup LRU symbols! Promotion will fail.\n");
     return -1;
 }
 
 /*****************************************************************************
  * ACCESS TRACKING (Hash Table)
  *****************************************************************************/
 struct access_record {
   struct hlist_node node;
   struct page *page;
   int count;
 };
 
 static DEFINE_HASHTABLE(access_map, 10); /* 1024 buckets */
 static DEFINE_SPINLOCK(access_lock);
 
 /*****************************************************************************
  * PROMOTION LOGIC
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
 
 static struct page *ktmm_new_page_node(struct page *src, unsigned long private)
 {
   int nid = (int)private;
   gfp_t gfp_mask = GFP_KERNEL | __GFP_HIGH | __GFP_MOVABLE | __GFP_THISNODE;
   return alloc_pages_node(nid, gfp_mask, 0);
 }
 
 static int kp_pre(struct kprobe *p, struct pt_regs *regs)
 {
   struct folio *folio;
   struct page *page;
   struct access_record *rec;
   struct promote_node *n;
   unsigned long flags;
   bool found = false;
 
   folio = (struct folio *)regs->di;
   if (!folio) return 0;
 
   if (folio_test_anon(folio)) return 0;
   if (folio_test_large(folio)) return 0;
   if (!folio_mapping(folio)) return 0;
 
   page = &folio->page;
 
   /* Only track pages on PMEM (Node != 0) */
   if (page_to_nid(page) == 0) return 0;
 
   spin_lock_irqsave(&access_lock, flags);
   
   hash_for_each_possible(access_map, rec, node, (unsigned long)page) {
     if (rec->page == page) {
       rec->count++;
       found = true;
       break;
     }
   }
 
   if (!found) {
     rec = kmalloc(sizeof(*rec), GFP_ATOMIC);
     if (rec) {
       rec->page = page;
       rec->count = 1;
       hash_add(access_map, &rec->node, (unsigned long)page);
     }
   }
   
   if (rec && rec->count >= HIGHEST_LEVEL) {
     hash_del(&rec->node);
     kfree(rec);
     spin_unlock_irqrestore(&access_lock, flags);
     
     n = kmalloc(sizeof(*n), GFP_ATOMIC);
     if (!n) return 0;
     
     INIT_LIST_HEAD(&n->link);
     get_page(page); /* Pin */
     n->page = page;
 
     spin_lock_irqsave(&promote_lock, flags);
     list_add_tail(&n->link, &promote_list);
     atomic_inc(&promote_count);
     spin_unlock_irqrestore(&promote_lock, flags);
     
     atomic64_inc(&promote_queued);
     return 0;
   }
 
   spin_unlock_irqrestore(&access_lock, flags);
   return 0;
 }
 
 /* Worker: Isolates and Migrates */
 static int promote_worker_fn(void *arg)
 {
   while (!kthread_should_stop()) {
     struct promote_node *batch[BATCH_N];
     int n = 0, i;
     unsigned long flags;
     LIST_HEAD(migrate_list);
 
     /* 1. Drain Queue */
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
 
     /* 2. Isolate Pages (CRITICAL STEP) */
     for (i = 0; i < n; i++) {
       struct promote_node *x = batch[i];
       struct page *page = x->page;
       struct folio *folio = page_folio(page);
 
       /* Try to isolate using kernel internal function */
       if (kernel_folio_isolate_lru && kernel_folio_isolate_lru(folio)) {
         list_add(&page->lru, &migrate_list);
       } else {
         /* Failed to isolate, drop it */
         put_page(page); 
       }
       kfree(x);
     }
 
     /* 3. Migrate */
     if (!list_empty(&migrate_list)) {
       unsigned int nr_succeeded = 0;
       
       /* Move to Node 0 (DRAM) */
       migrate_pages(&migrate_list, ktmm_new_page_node, NULL, 
               0, MIGRATE_SYNC, MR_NUMA_MISPLACED, &nr_succeeded);
       
       if (nr_succeeded > 0)
         atomic64_add(nr_succeeded, &total_pages_promoted);
       
       /* Cleanup failures */
       if (!list_empty(&migrate_list)) {
         struct page *p, *tmp;
         list_for_each_entry_safe(p, tmp, &migrate_list, lru) {
           list_del(&p->lru);
           
           /* Use dynamic putback */
           if (kernel_folio_putback_lru)
             kernel_folio_putback_lru(page_folio(p));
           else
             put_page(p); /* Fallback */
             
           atomic64_inc(&promote_failed);
         }
       }
     }
     cond_resched();
   }
   return 0;
 }
 
 /*****************************************************************************
  * DEMOTION LOGIC
  *****************************************************************************/
 
 /* Hooks */
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
 
 static unsigned long scan_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec, struct scan_control *sc, enum lru_list lru, struct pglist_data *pgdat)
 {
   LIST_HEAD(folio_list);
   LIST_HEAD(l_migrate);
   unsigned long nr_scanned, nr_taken;
   unsigned int nr_succeeded = 0;
   unsigned long vm_flags;
   int file = is_file_lru(lru);
 
   /* Only scan Node 0 for Demotion */
   if (pgdat->node_id != 0) return 0;
 
   ktmm_lru_add_drain();
   spin_lock_irq(&lruvec->lru_lock);
   nr_taken = ktmm_isolate_lru_folios(nr_to_scan, lruvec, &folio_list, &nr_scanned, sc, lru);
   __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
   spin_unlock_irq(&lruvec->lru_lock);
 
   if (nr_taken == 0) return 0;
 
   if (!list_empty(&folio_list)) {
     struct folio *folio, *next;
     list_for_each_entry_safe(folio, next, &folio_list, lru) {
       /* If unreferenced, move to migrate list */
       if (!ktmm_folio_referenced(folio, 0, sc->target_mem_cgroup, &vm_flags)) {
         list_del(&folio->lru);
         list_add(&folio->lru, &l_migrate);
       }
     }
   }
 
   if (!list_empty(&l_migrate)) {
     int target_nid = pmem_node_id;
     /* Force migration to PMEM */
     migrate_pages(&l_migrate, ktmm_new_page_node, NULL, 
             (unsigned long)target_nid, MIGRATE_SYNC_LIGHT, 
             MR_NUMA_MISPLACED, &nr_succeeded);
     
     if (nr_succeeded > 0)
       atomic64_add(nr_succeeded, &total_pages_demoted);
     
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
   struct mem_cgroup *memcg = ktmm_mem_cgroup_iter(NULL, NULL, reclaim);
   sc->target_mem_cgroup = memcg;
   int nid = pgdat->node_id;
 
   do {
     struct lruvec *lruvec = &memcg->nodeinfo[nid]->lruvec;
     cond_resched();
     /* Scan 1024 pages per pass */
     scan_inactive_list(1024, lruvec, sc, LRU_INACTIVE_FILE, pgdat);
     scan_inactive_list(1024, lruvec, sc, LRU_INACTIVE_ANON, pgdat);
   } while ((memcg = ktmm_mem_cgroup_iter(NULL, memcg, NULL)));
 }
 
 static int demote_scanner_fn(void *p) 
 {
   pg_data_t *pgdat = (pg_data_t *)p;
   struct mem_cgroup_reclaim_cookie reclaim = { .pgdat = pgdat };
   struct scan_control sc = { .nr_to_reclaim = SWAP_CLUSTER_MAX, .may_unmap = 1, .may_swap = 1 };
   struct task_struct *task = current;
   
   task->flags |= PF_MEMALLOC | PF_KSWAPD;
 
   while (!kthread_should_stop()) {
     /* Force scan on Node 0 (DRAM) */
     if (pgdat->node_id == 0) {
       scan_node(pgdat, &sc, &reclaim);
     }
     
     if (kthread_should_stop()) break;
     schedule_timeout_interruptible(1 * HZ); /* 1 sec scan interval */
   }
 
   task->flags &= ~(PF_MEMALLOC | PF_KSWAPD);
   return 0;
 }
 
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
   printk(KERN_INFO "KTMM STATS: Promoted: %llu (Fail: %llu) | Demoted: %llu | Queued: %llu\n",
          (u64)atomic64_read(&total_pages_promoted), 
          (u64)atomic64_read(&promote_failed),
          (u64)atomic64_read(&total_pages_demoted),
          (u64)atomic64_read(&promote_queued));
   mod_timer(t, jiffies + 5 * HZ);
 }
 static DEFINE_TIMER(stats_timer, print_stats);
 
 int tmemd_start_available(void) 
 {
   int nid, ret;
   
   set_ktmm_scan();
   
   /* LOOKUP INTERNAL KERNEL SYMBOLS */
   if (lookup_internal_functions() < 0) return -1;
 
   ret = install_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 
   kp.symbol_name = "folio_mark_accessed";
   kp.pre_handler = kp_pre;
   if (register_kprobe(&kp)) {
     pr_err("KTMM: Failed to register kprobe\n");
     return -1;
   }
 
   promote_worker_task = kthread_run(promote_worker_fn, NULL, "ktmm_promote");
   
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
   struct access_record *rec;
   struct hlist_node *tmp;
   int bkt;
 
   del_timer_sync(&stats_timer);
   unregister_kprobe(&kp);
   
   if (promote_worker_task) kthread_stop(promote_worker_task);
 
   for_each_online_node(nid) {
     if (tmemd_list[nid]) kthread_stop(tmemd_list[nid]);
   }
   uninstall_hooks(vmscan_hooks, ARRAY_SIZE(vmscan_hooks));
 
   hash_for_each_safe(access_map, bkt, tmp, rec, node) {
     hash_del(&rec->node);
     kfree(rec);
   }
 }