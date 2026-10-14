/*
 * Kernel Module for Tiered Memory System
 *
 * Copyright (c) FreshlyCutWax
 */

#define pr_fmt(fmt) "[ KTMM Mod ] " fmt


#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/version.h>

#include "ktmm_vmscan.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jared Draper, Josh Borthick, Grant Wilke, Camilo Palomino");
MODULE_DESCRIPTION("Tiered Memory Module.");


/**
 * module init - called on module installation
 */
static int __init tmem_init(void) {
	int ret;

/*
 * 6.1.x only: the private struct scan_control copy, isolate_lru_folios(),
 * prep_transhuge_page() and the migrate_pages() callback types all match
 * 6.1 and change in later releases.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)
	pr_info("Module initializing..\n");
	ret = tmemd_start_available();
#else
	ret = -EINVAL;
	pr_info("Unsupported kernel version (6.1.x required).\n");
#endif

	return ret;
}


/**
 * module exit - called on module exit
 */
static void __exit tmem_exit(void) {
	pr_info("Module exiting..\n");
	tmemd_stop_all();
}


module_init(tmem_init);
module_exit(tmem_exit);
