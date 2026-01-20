/* =========================
 * uts_promote_set_bulk.c (module rewritten to call the new bulk API)
 * Ported to kernel 6.1+
 * ========================= */

// uts_promote_set_bulk.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>

#include <linux/mm.h>
#include <linux/page_ext.h>
#include <linux/page-flags.h>    /* 6.1: explicit include for page flag macros */
#include <linux/huge_mm.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

#define HIGHEST_LEVEL 7
#define BATCH_N 32
#define NODE_A 0
#define NODE_B 1
#define WORK_SLEEP_MS 10

static atomic64_t aging_offset = ATOMIC64_INIT(0);
static struct task_struct *worker_task;
static atomic64_t mig_attempted = ATOMIC64_INIT(0);
static atomic64_t mig_succeeded = ATOMIC64_INIT(0);

/* new bulk migrator */
extern int uts_migrate_file_pages_bulk_vec(struct page **pages, int nr_pages, int target_nid);

static __always_inline int other_nid(int nid)
{
	return (nid == NODE_A) ? NODE_B : NODE_A;
}

struct promote_node {
	struct list_head link;
	struct page *page;
};

static LIST_HEAD(promote_list);
static DEFINE_SPINLOCK(promote_lock);
static atomic_t promote_count = ATOMIC_INIT(0);

static struct kprobe kp;

static __always_inline u64 now_off(void)
{
	return (u64)atomic64_read(&aging_offset);
}

static __always_inline u64 clamp_u64(u64 v, u64 lo, u64 hi)
{
	if (v < lo) return lo;
	if (v > hi) return hi;
	return v;
}

static __always_inline bool is_file_page(struct page *page)
{
	struct address_space *mapping;

	if (PageAnon(page)) return false;
	if (PageHuge(page) || PageTransHuge(page) || PageCompound(page)) return false;

	/*
	 * 6.1: page_mapping() still works but can return NULL for various reasons.
	 * Cache the result to avoid calling it twice.
	 */
	mapping = page_mapping(page);
	if (!mapping) return false;
	if (!mapping->host) return false;
	return true;
}

static int kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct page *page;
	struct page_ext *pe;
	u64 off, slot, new_slot, eff;
	struct promote_node *n;
	unsigned long flags;

	page = (struct page *)regs->di;
	if (!page) return 0;

	if (!is_file_page(page)) return 0;

	/*
	 * 6.1 API change: lookup_page_ext() replaced with page_ext_get()/page_ext_put()
	 *
	 * In kernel 5.17+, the page_ext subsystem changed to require explicit locking.
	 * page_ext_get() acquires a local_lock and returns the page_ext pointer.
	 * page_ext_put() releases the lock.
	 *
	 * This is safe in kprobe context as it uses local_lock_irq internally.
	 */
	pe = page_ext_get(page);
	if (!pe) return 0;

	off = now_off();
	slot = READ_ONCE(pe->uts_slot_id);
	new_slot = clamp_u64(slot + 1, off + 1, off + HIGHEST_LEVEL);
	WRITE_ONCE(pe->uts_slot_id, new_slot);

	/* 6.1: Must release page_ext lock before doing anything else */
	page_ext_put();

	eff = (new_slot > off) ? (new_slot - off) : 0;
	if (eff < HIGHEST_LEVEL)
		return 0;

	if (uts_page_in_promote(page))
		return 0;

	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n)
		return 0;
	INIT_LIST_HEAD(&n->link);

	get_page(page);          /* promote-set pin */
	n->page = page;

	spin_lock_irqsave(&promote_lock, flags);
	if (uts_page_in_promote(page)) {
		spin_unlock_irqrestore(&promote_lock, flags);
		put_page(page);
		kfree(n);
		return 0;
	}
	list_add_tail(&n->link, &promote_list);
	atomic_inc(&promote_count);
	uts_page_set_in_promote(page, true);
	spin_unlock_irqrestore(&promote_lock, flags);

	return 0;
}

static int worker_fn(void *arg)
{
	while (!kthread_should_stop()) {
		struct promote_node *batch[BATCH_N];
		int n = 0, i;
		unsigned long flags;

		/* vectors per destination */
		struct page *vecA[BATCH_N];
		struct page *vecB[BATCH_N];
		int nA = 0, nB = 0;

		/* bulk-pop promote_nodes */
		spin_lock_irqsave(&promote_lock, flags);
		while (n < BATCH_N && !list_empty(&promote_list)) {
			struct promote_node *x =
				list_first_entry(&promote_list, struct promote_node, link);
			list_del_init(&x->link);
			atomic_dec(&promote_count);
			batch[n++] = x;
		}
		spin_unlock_irqrestore(&promote_lock, flags);

		if (n == 0) {
			msleep(WORK_SLEEP_MS);
			continue;
		}

		/* build vectors; DO NOT touch page->lru here */
		for (i = 0; i < n; i++) {
			struct promote_node *x = batch[i];
			struct page *page = x->page;
			int dst = other_nid(page_to_nid(page));

			/* drop promote-set membership now (page is valid) */
			uts_page_set_in_promote(page, false);

			if (dst == NODE_A)
				vecA[nA++] = page;
			else
				vecB[nB++] = page;

			kfree(x);
		}

		/* one bulk call per destination */
		if (nA) {
			int retA;

			atomic64_add(nA, &mig_attempted);
			retA = uts_migrate_file_pages_bulk_vec(vecA, nA, NODE_A);

			/*
			 * For any entry still non-NULL, bulk did NOT isolate it,
			 * so it did NOT consume the promote-set pin -> we must drop it.
			 */
			for (i = 0; i < nA; i++) {
				if (vecA[i])
					put_page(vecA[i]);
			}

			if (retA >= 0)
				atomic64_add((u64)(nA - retA), &mig_succeeded);

			pr_info("uts: bulk dst=%d n=%d ret=%d\n", NODE_A, nA, retA);
		}

		if (nB) {
			int retB;

			atomic64_add(nB, &mig_attempted);
			retB = uts_migrate_file_pages_bulk_vec(vecB, nB, NODE_B);

			for (i = 0; i < nB; i++) {
				if (vecB[i])
					put_page(vecB[i]);
			}

			if (retB >= 0)
				atomic64_add((u64)(nB - retB), &mig_succeeded);

			pr_info("uts: bulk dst=%d n=%d ret=%d\n", NODE_B, nB, retB);
		}

		pr_info("uts: attempted=%llu succeeded=%llu\n",
			(unsigned long long)atomic64_read(&mig_attempted),
			(unsigned long long)atomic64_read(&mig_succeeded));

		cond_resched();
	}
	return 0;
}

static int __init uts_init(void)
{
	kp.symbol_name = "mark_page_accessed";
	kp.pre_handler = kp_pre;
	if (register_kprobe(&kp))
		return -EINVAL;

	worker_task = kthread_run(worker_fn, NULL, "uts_promote_worker");
	if (IS_ERR(worker_task)) {
		worker_task = NULL;
		unregister_kprobe(&kp);
		return -ENOMEM;
	}

	pr_info("uts: loaded\n");
	return 0;
}

static void __exit uts_exit(void)
{
	struct promote_node *n;
	unsigned long flags;

	unregister_kprobe(&kp);

	if (worker_task) {
		kthread_stop(worker_task);
		worker_task = NULL;
	}

	/* drain promote_list */
	while (1) {
		spin_lock_irqsave(&promote_lock, flags);

		if (list_empty(&promote_list)) {
			spin_unlock_irqrestore(&promote_lock, flags);
			break;
		}

		n = list_first_entry(&promote_list, struct promote_node, link);
		list_del_init(&n->link);
		atomic_dec(&promote_count);

		spin_unlock_irqrestore(&promote_lock, flags);

		uts_page_set_in_promote(n->page, false);
		put_page(n->page);
		kfree(n);
	}

	pr_info("uts: unloaded\n");
}

module_init(uts_init);
module_exit(uts_exit);