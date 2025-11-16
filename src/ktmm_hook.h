/*
 * KTMM HOOK - Kernel function hooking for KTMM Module
 *
 * Copyright (c) FreshlyCutWax
 */
#ifndef KTMM_HOOK_HEADER_H
#define KTMM_HOOK_HEADER_H

#include <linux/ftrace.h>

/**
 * ktmm_hook - Module Hook Structure
 * 
 * @symbol_name:	name of kernel symbol to hook
 * @module_function:	raw ptr to module object
 * @kernel_function:	raw ptr to kernel object
 *
 * Do not use this directly. Use the macro to create/initialize a hook instead.
 */
struct ktmm_hook {
	const char *symbol_name;
	void *module_function;
	void *kernel_function;

	/* address to kernel function */
	unsigned long kernel_addr;

	/* address to module function */
	unsigned long module_addr;

	struct ftrace_ops ops;
};


/**
 * @name: 		name of kernel symbol to hook
 * @mfunc:		module function
 * @kfunc:		kernel function
 *
 * To be used for initializing struct ktmm_hook.
 */
#define HOOK(name, mfunc, kfunc)		\
	{					\
		.symbol_name = (name),		\
		.module_function = (mfunc),	\
		.kernel_function = (kfunc),	\
	}

/**
 * uninstall_hooks - uninstall module function hooks
 *
 * @hooks:	array of hooks to uninstall
 * @count:	size of the array (use ARRAY_SIZE() macro)
 *
 * @returns:	none
 *
 * This should be called by other parts of the module to uninstall hooks.
 *
 * The install_hooks() will call this function in case of failure to install
 * hooks. Hooks are uninstalled in reverse order, where the last hooks is the
 * first to be uninstalled.
 */
void uninstall_hooks(struct ktmm_hook *hooks, size_t count);


/**
 * install_hooks - install module function hooks
 *
 * @hooks:	array of hooks to install
 * @count:	size of the array (use ARRAY_SIZE() macro)
 *
 * @returns:	0 or error
 *
 * This should be called by other parts of the module to install hooks.
 */
int install_hooks(struct ktmm_hook *hooks, size_t count);


unsigned long symbol_lookup(const char *symbol_name);

#endif /* KTMM_HOOK_HEADER_H */
