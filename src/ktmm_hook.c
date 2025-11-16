/*
 * Implementation of function hooking.
 *
 * Copyright (c) FreshlyCutWax
 */

#define pr_fmt(fmt) "[ KTMM Mod ] hook - " fmt

#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

#include "ktmm_hook.h"


/**
 * symbol_lookup - Lookup kernel symbol by name
 *
 * @symbol_name:	name of symbol to lookup
 * 
 * @returns:		address of symbol (0 for failure)
 *
 * This semantically the same as kallsyms_lookup_name. Should only be used on
 * functions.
 *
 * The kprobes API can be found in:
 * 	include/linux/kprobes.h
 */
unsigned long symbol_lookup(const char *symbol_name)
{
	unsigned long ret;

	struct kprobe kp = {
		.symbol_name = symbol_name,
	};

	if(register_kprobe(&kp) < 0) return 0;
	ret = (unsigned long) kp.addr;
	unregister_kprobe(&kp);

	return ret;
}


/**
 * hook_set_ip - set assembly instruction pointer for hooked function
 *
 * @ip:		instruction ptr of kernel object being traced
 * @parent_ip:	instruction ptr of caller
 * @ops:	ftrace operation structure
 * @regs:	wrapped registers structure (struct reg)
 *
 * @returns:	none
 *
 * This will set the instruction pointer for the hooked function to jump to the
 * module's desired function. Not all parameters are used, but this needs to
 * support the same parameter list as ftrace_func_t to work.
 *
 * The ftrace API can be found in:
 * 	include/linux/ftrace.h
 */
static void notrace hook_function_set_ip(unsigned long ip,
				unsigned long parent_ip,
				struct ftrace_ops *ops,
				struct ftrace_regs *regs)
{
	struct ktmm_hook *hook = container_of(ops, struct ktmm_hook, ops);

	ftrace_instruction_pointer_set(regs, hook->module_addr);
}

/**
 * register_hook - install a single hook into the kernel
 *
 * @hook:	initialized hook to install
 *
 * @returns:	0 or error value
 *
 * The ftrace API can be found in:
 * 	include/linux/ftrace.h
 */
static int register_hook(struct ktmm_hook *hook) 
{
	int err;

	/* resolve addresses */
	hook->module_addr = (unsigned long) hook->module_function;
	hook->kernel_addr = symbol_lookup(hook->symbol_name);

	if (!hook->kernel_addr)
		return -ENOENT;
	
	/*
	 * This is ugly, so explanation:
	 *
	 * Dereference the address value that points to the kernel function and
	 * set it to the address found by symbol lookup. We skip over the
	 * instruction that jumps so we don't end in infinite recursion.
	 */
	*((unsigned long *) hook->kernel_function) = hook->kernel_addr 
							+ MCOUNT_INSN_SIZE;
	

	/* set ftrace operation flags */
	hook->ops.func = hook_function_set_ip;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS 	//save registers
			| FTRACE_OPS_FL_IPMODIFY 	//modify instruction ptr
			| FTRACE_OPS_FL_RECURSION;	//recursion protection


	/* filter ftrace filter for hooked function */
	err = ftrace_set_filter_ip(&hook->ops, hook->kernel_addr, 0, 0);
	if (err)
		return err;

	
	/* register the ftrace */
	err = register_ftrace_function(&hook->ops);
	if (err) {
		ftrace_set_filter_ip(&hook->ops, hook->kernel_addr, 1, 0);
		
		return err;
	}

	return 0;
}

/**
 * unregister_hook - uninstall a single hook
 *
 * @hook:	hook to uninstall
 *
 * @returns:	none
 */
static void unregister_hook(struct ktmm_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err)
		pr_info("Unable to unregister hook -> %s", hook->symbol_name);

	err = ftrace_set_filter_ip(&hook->ops, hook->kernel_addr, 1, 0);
	if (err)
		pr_info("Unable to remove ftrace filter -> %s", 
			hook->symbol_name);
}


/**
 * This is a public function to be used by the rest of the module.
 */
void uninstall_hooks(struct ktmm_hook *hooks, size_t count)
{
	size_t i = count;

	while (i != 0) unregister_hook(&hooks[--i]);
}


/**
 * This is a public function to be used by the rest of the module.
 */
int install_hooks(struct ktmm_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {

		err = register_hook(&hooks[i]);

		if (err) goto hook_install_error;
	}

	return 0;

hook_install_error:
	uninstall_hooks(hooks, i);
	
	return err;
}
