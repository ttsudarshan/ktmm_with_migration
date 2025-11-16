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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
	pr_info("Module initializing..\n");
	ret = tmemd_start_available();
#else
	ret = -EFAULT;
	pr_info("Minimum kernel version not met.");
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
