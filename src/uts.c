/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PAGE_EXT_H
#define __LINUX_PAGE_EXT_H
 
#include <linux/types.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/list.h>
 
struct pglist_data;
 
struct page_ext_operations {
	size_t offset;
	size_t size;
	bool (*need)(void);
	void (*init)(void);
};
 
#ifdef CONFIG_PAGE_EXTENSION
 
enum page_ext_flags {
	PAGE_EXT_OWNER,
	PAGE_EXT_OWNER_ALLOCATED,
#if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
	PAGE_EXT_YOUNG,
	PAGE_EXT_IDLE,
#endif
};
 
/*
 * Page Extension can be considered as an extended mem_map.
 * A page_ext page is associated with every page descriptor. The
 * page_ext helps us add more information about the page.
 * All page_ext are allocated at boot or memory hotplug event,
 * then the page_ext for pfn always exists.
 */
struct page_ext {
	unsigned long flags;
 
	/* UTS: hotness / promotion sets */
	u64 uts_slot_id;
	u8  uts_in_promote;
	u8  uts_in_demote;
 
	/*
	 * UTS: DRAM level tracking (2 lists)
	 * 0 = not tracked / uninitialized
	 * 1 = L0 (cold, demote-candidate)
	 * 2 = L1 (hot)
	 */
	u8  uts_dram_state;
	struct list_head uts_dram_link;
	unsigned long uts_dram_pfn;
};
 
extern unsigned long page_ext_size;
extern void pgdat_page_ext_init(struct pglist_data *pgdat);
 
#ifdef CONFIG_SPARSEMEM
static inline void page_ext_init_flatmem(void)
{
}
extern void page_ext_init(void);
static inline void page_ext_init_flatmem_late(void)
{
}
#else
extern void page_ext_init_flatmem(void);
extern void page_ext_init_flatmem_late(void);
static inline void page_ext_init(void)
{
}
#endif
 
struct page_ext *lookup_page_ext(const struct page *page);
 
static inline struct page_ext *page_ext_next(struct page_ext *curr)
{
	void *next = curr;
	next += page_ext_size;
	return next;
}
 
#else /* !CONFIG_PAGE_EXTENSION */
 
struct page_ext;
 
static inline void pgdat_page_ext_init(struct pglist_data *pgdat)
{
}
 
static inline struct page_ext *lookup_page_ext(const struct page *page)
{
	return NULL;
}
 
static inline void page_ext_init(void)
{
}
 
static inline void page_ext_init_flatmem_late(void)
{
}
 
static inline void page_ext_init_flatmem(void)
{
}
 
#endif /* CONFIG_PAGE_EXTENSION */
 
/* =========================
 * UTS inline helpers
 * ========================= */
 
static __always_inline u64 uts_page_slot_id_read(struct page *page)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return 0;
	return READ_ONCE(pe->uts_slot_id);
}
 
static __always_inline void uts_page_slot_id_write(struct page *page, u64 v)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return;
	WRITE_ONCE(pe->uts_slot_id, v);
}
 
static __always_inline bool uts_page_in_promote(struct page *page)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return false;
	return READ_ONCE(pe->uts_in_promote);
}
 
static __always_inline void uts_page_set_in_promote(struct page *page, bool v)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return;
	WRITE_ONCE(pe->uts_in_promote, v);
}
 
static __always_inline bool uts_page_in_demote(struct page *page)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return false;
	return READ_ONCE(pe->uts_in_demote);
}
 
static __always_inline void uts_page_set_in_demote(struct page *page, bool v)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return;
	WRITE_ONCE(pe->uts_in_demote, v);
}
 
/*
 * DRAM 2-level tracking helpers.
 *
 * IMPORTANT invariant:
 * - If uts_dram_state == 0, uts_dram_link is considered uninitialized and
 *   must NOT be list_del/list_move'd.
 * - On first insertion, caller must INIT_LIST_HEAD(&pe->uts_dram_link)
 *   then link it into a list and set state non-zero.
 */
 
#define UTS_DRAM_NONE 0
#define UTS_DRAM_L0   1
#define UTS_DRAM_L1   2
 
static __always_inline u8 uts_page_dram_state_read(struct page *page)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return UTS_DRAM_NONE;
	return READ_ONCE(pe->uts_dram_state);
}
 
static __always_inline void uts_page_dram_state_write(struct page *page, u8 v)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return;
	WRITE_ONCE(pe->uts_dram_state, v);
}
 
static __always_inline struct list_head *uts_page_dram_link(struct page *page)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return NULL;
	return &pe->uts_dram_link;
}
 
/* Safe check: is this page currently tracked in DRAM lists? */
static __always_inline bool uts_page_dram_tracked(struct page *page)
{
	return uts_page_dram_state_read(page) != UTS_DRAM_NONE;
}
 
/* Safe removal helper: only removes if tracked (state != 0). */
static __always_inline void uts_page_dram_unlink_if_tracked(struct page *page)
{
	struct page_ext *pe = lookup_page_ext(page);
	if (!pe)
		return;
 
	if (READ_ONCE(pe->uts_dram_state) == UTS_DRAM_NONE)
		return;
 
	list_del_init(&pe->uts_dram_link);
	WRITE_ONCE(pe->uts_dram_state, UTS_DRAM_NONE);
}
 
#endif /* __LINUX_PAGE_EXT_H */
 