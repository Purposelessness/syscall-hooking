#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <asm/signal.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

#define TARGET_UID 1000
#define LOG_FILENAME "/tmp/main.log"
#define LOG_DMESG 0

MODULE_DESCRIPTION("Tracking certain user activity");
MODULE_AUTHOR("purposelessness");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
/*
 * Returns the address of system call `name` in kernel memeory.
 */
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#else
/*
 * Since kernel ver. 5.7.0 `kallsyms_lookup_name()` is not exported anymore.
 */
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	if (register_kprobe(&kp) < 0) return 0;
	unsigned long retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#endif

/*
 * Aliases for older versions of linux
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE

#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * struct ftrace_hook	describes hooked function
 *
 * @name:		name of hooked function
 * @function:		function to replace hooked one
 * @original:		pointer to a hooked function
 *
 * @address:		address of a hooked function
 * @ops:		flags of ftrace
 *
 * User should fill in &name, &function and &original fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

/*
 * fh_resolve_hook_address() - resolve address of a symbol being hooked
 *
 * @hook: contains a symbol
 *
 * Returns: zero on success, minus one with errno set otherwise.
 */
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (hook->address == 0) {
		pr_err("tracker: unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long *)hook->original) = hook->address;

	return 0;
}

/*
 * fh_ftrace_thunk() - callback function
 *
 * @ip: instruction pointer of a function that is being traced
 * @parent_ip: ip of a function that called the function begin traced
 * @op: pointer to `struct ftrace_ops ops` field inside `struct ftrace_hook`
 * @fregs: registers' state
 */
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	// `container_of()` returns struct where `ops` is located
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	/*
	 * Prevent recursive loops when hooking by using `within_module()` check
	 * Set ip register to function stored in `ftrace_hook`
	 */
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
}

/*
 * fh_install_hook() - register and enable a single hook
 *
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int retval = fh_resolve_hook_address(hook);
	if (retval != 0) {
		pr_err("tracker: fh_resolve_hook_address() failed: %d\n", retval);
		return retval;
	}

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION
	                | FTRACE_OPS_FL_IPMODIFY;

	retval = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (retval != 0) {
		pr_err("tracker: ftrace_set_filter_ip() failed: %d\n", retval);
		return retval;
	}

	retval = register_ftrace_function(&hook->ops);
	if (retval != 0) {
		pr_err("tracker: register_ftrace_function() failed: %d\n", retval);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return retval;
	}

	return 0;
}

/*
 * fh_remove_hook() - disable and unregister a single hook
 *
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int retval = unregister_ftrace_function(&hook->ops);
	if (retval != 0) {
		pr_err("tracker: unregister_ftrace_function() failed: %d\n", retval);
	}

	retval = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (retval != 0) {
		pr_err("tracker: ftrace_set_filter_ip() failed: %d\n", retval);
	}
}

/*
 * fh_install_hooks() - register and enable multiple hooks
 *
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int retval;
	size_t i;

	for (i = 0; i < count; ++i) {
		retval = fh_install_hook(&hooks[i]);
		if (retval != 0)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return retval;
}

/*
 * fh_remove_hooks() - disable and unregister multiple hooks
 *
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
		fh_remove_hook(&hooks[i]);
}

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#pragma GCC optimize("-fno-optimize-sibling-calls")

static struct file *fp;
static loff_t fp_offset;

static inline int file_open(const char *filename, int flags, int mode)
{
	int retval = 0;

	fp = filp_open(filename, flags, mode);
	if (IS_ERR(fp)) {
		retval = PTR_ERR(fp);
		return retval;
	}

	fp_offset = 0;

	return 0;
}

static inline void file_close(void)
{
	filp_close(fp, NULL);
}

static inline int file_write(char *data, size_t size)
{
	return kernel_write(fp, data, size, &fp_offset);
}

/*
 * Duplicates string from user space to kernel space.
 *
 * Returns: string from kernel space.
 */
static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (kernel_filename == NULL)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

/*
 * Converts array of strings from user space to a string from kernel space.
 *
 * Returns: string from kernel space.
 */
static char *convert_params_to_str(const char __user *const __user *params)
{
	size_t sz = 4096;
	size_t cur_sz = 0;
	char *tmp;
	char *duplicate_str;
	char *kernel_str;

	duplicate_str = kmalloc(4096, GFP_KERNEL);
	if (duplicate_str == NULL)
		return NULL;

	kernel_str = kmalloc(4096, GFP_KERNEL);
	if (kernel_str == NULL) {
		kfree(duplicate_str);
		return NULL;
	}

	for (size_t i = 0; params[i] != NULL; ++i) {
		if (strncpy_from_user(duplicate_str, params[i], 4096) < 0)
			goto error;

		cur_sz += strlen(duplicate_str) + 2;
		if (cur_sz >= sz) {
			tmp = krealloc(kernel_str, sz += 4096, GFP_KERNEL);
			if (tmp == NULL)
				goto error;
			kernel_str = tmp;
		}
		strcat(kernel_str, duplicate_str);
		strcat(kernel_str, ", ");
	}

	kfree(duplicate_str);
	kernel_str[cur_sz - 2] = '\0';

	return kernel_str;

error:
	kfree(kernel_str);
	kfree(duplicate_str);
	return NULL;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_openat)(struct pt_regs *regs);

static asmlinkage long fh_sys_openat(struct pt_regs *regs)
{
	long retval;
	char *kernel_filename;
	struct task_struct *task = current; 
	uid_t uid = task->cred->uid.val;
	uid_t suid = task->cred->suid.val;
	uid_t euid = task->cred->euid.val;

	if (uid == TARGET_UID) {
		kernel_filename = duplicate_filename((void*) regs->si);
		int flags = regs->dx;
		unsigned short mode = regs->r10;

		const char *const TEMPLATE =  "[%lld] tracker: openat(%s, %o, %o)"
			"\t(uid=%d, suid=%d, euid=%d)\n";
		const size_t LINE_LENGTH = strlen(TEMPLATE) + 
			strlen(kernel_filename) + 40;
		char line[LINE_LENGTH];

		snprintf(line, LINE_LENGTH, TEMPLATE, ktime_get_real_seconds(),
				kernel_filename, flags, mode, uid, suid, euid);

		file_write(line, strlen(line));

#if LOG_DMESG
		pr_info("%s", line);
#endif

		kfree(kernel_filename);
	}

	retval = real_sys_openat(regs);

	return retval;
}
#else
static asmlinkage long (*real_sys_openat)(int dfd, const char __user *filename,
				int flags, umode_t mode);

static asmlinkage long fh_sys_openat(int dfd, const char __user *filename,
				int flags, umode_t mode)
{
	long retval;
	char *kernel_filename;
	struct task_struct *task = current;
	uid_t uid = task->cred->uid.val;
	uid_t suid = task->cred->suid.val;
	uid_t euid = task->cred->euid.val;

	if (uid == TARGET_UID) {
		kernel_filename = duplicate_filename(filename);

		const char *const TEMPLATE =  "[%lld] tracker: openat(%s, %o, %o)"
			"\t(uid=%d, suid=%d, euid=%d)\n";
		const size_t LINE_LENGTH = strlen(TEMPLATE) + 
			strlen(kernel_filename) + 40;
		char line[LINE_LENGTH];

		snprintf(line, LINE_LENGTH, TEMPLATE, ktime_get_real_seconds(),
				kernel_filename, flags, mode, uid, suid, euid);

		file_write(line, strlen(line));

#if LOG_DMESG
		pr_info("%s", line);
#endif

		kfree(kernel_filename);
	}

	retval = real_sys_openat(dfd, filename, flags, mode);

	return retval;
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_chdir)(struct pt_regs *regs);

static asmlinkage long fh_sys_chdir(struct pt_regs *regs)
{
	long retval;
	char *kernel_filename;
	struct task_struct *task = current; 
	uid_t uid = task->cred->uid.val;
	uid_t suid = task->cred->suid.val;
	uid_t euid = task->cred->euid.val;

	if (uid == TARGET_UID) {
		kernel_filename = duplicate_filename((void*) regs->di);

		const char *const TEMPLATE =  "[%lld] tracker: chdir(%s)"
			"\t(uid=%d, suid=%d, euid=%d)\n";
		const size_t LINE_LENGTH = strlen(TEMPLATE) + 
			strlen(kernel_filename) + 30;
		char line[LINE_LENGTH];

		snprintf(line, LINE_LENGTH, TEMPLATE, ktime_get_real_seconds(),
				kernel_filename, uid, suid, euid);

		file_write(line, strlen(line));

#if LOG_DMESG
		pr_info("%s", line);
#endif

		kfree(kernel_filename);
	}

	retval = real_sys_chdir(regs);

	return retval;
}
#else
static asmlinkage long (*real_sys_chdir)(const char __user *filename);

static asmlinkage long fh_sys_chdir(const char __user *filename)
{
	long retval;
	char *kernel_filename;
	struct task_struct *task = current; 
	uid_t uid = task->cred->uid.val;
	uid_t suid = task->cred->suid.val;
	uid_t euid = task->cred->euid.val;

	if (uid == TARGET_UID) {
		kernel_filename = duplicate_filename(filename);

		const char *const TEMPLATE =  "[%lld] tracker: chdir(%s)"
			"\t(uid=%d, suid=%d, euid=%d)\n";
		const size_t LINE_LENGTH = strlen(TEMPLATE) + 
			strlen(kernel_filename) + 30;
		char line[LINE_LENGTH];

		snprintf(line, LINE_LENGTH, TEMPLATE, ktime_get_real_seconds(),
				kernel_filename, uid, suid, euid);

		file_write(line, strlen(line));

#if LOG_DMESG
		pr_info("%s", line);
#endif

		kfree(kernel_filename);
	}

	retval = real_sys_chdir(filename);

	return retval;
}
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long retval;
	char *kernel_filename;
	char *kernel_argv;
	struct task_struct *task = current; 
	uid_t uid = task->cred->uid.val;
	uid_t suid = task->cred->suid.val;
	uid_t euid = task->cred->euid.val;

	if (uid == TARGET_UID) {
		kernel_filename = duplicate_filename((void *)regs->di);
		kernel_argv = convert_params_to_str((void *)regs->si);

		const char *const TEMPLATE =  "[%lld] tracker: execve(%s, {%s})"
			"\t(uid=%d, suid=%d, euid=%d)\n";
		const size_t LINE_LENGTH = strlen(TEMPLATE) + 
			strlen(kernel_filename) + strlen(kernel_argv) + 30;
		char line[LINE_LENGTH];

		snprintf(line, LINE_LENGTH, TEMPLATE, ktime_get_real_seconds(),
				kernel_filename, kernel_argv, uid, suid, euid);

		file_write(line, strlen(line));

#if LOG_DMESG
		pr_info("%s", line);
#endif

		kfree(kernel_filename);
		kfree(kernel_argv);
	}

	retval = real_sys_execve(regs);

	return retval;
}
#else
static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

static asmlinkage long (*fh_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);
{
	long retval;
	char *kernel_filename;
	struct task_struct *task = current; 
	uid_t uid = task->cred->uid.val;
	uid_t suid = task->cred->suid.val;
	uid_t euid = task->cred->euid.val;

	if (uid == TARGET_UID) {
		kernel_filename = duplicate_filename(filename);
		kernel_argv = convert_params_to_str(argv);

		const char *const TEMPLATE =  "[%lld] tracker: execve(%s, {%s})"
			"\t(uid=%d, suid=%d, euid=%d)\n";
		const size_t LINE_LENGTH = strlen(TEMPLATE) + 
			strlen(kernel_filename) + strlen(kernel_argv) + 30;
		char line[LINE_LENGTH];

		snprintf(line, LINE_LENGTH, TEMPLATE, ktime_get_real_seconds(),
				kernel_filename, kernel_argv, uid, suid, euid);

		file_write(line, strlen(line));

#if LOG_DMESG
		pr_info("%s", line);
#endif

		kfree(kernel_filename);
		kfree(kernel_argv);
	}

	retval = real_sys_execve(filename, argv, envp);

	return retval;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points 
 * in newer kernels.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif


#define HOOK(_name, _function, _original)   	\
	{                                   	\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),    	\
		.original = (_original),    	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("sys_openat", fh_sys_openat, &real_sys_openat),
	HOOK("sys_chdir", fh_sys_chdir, &real_sys_chdir),
	HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};

static int fh_init(void)
{
	int retval = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (retval != 0)
		return retval;
	file_open(LOG_FILENAME, O_RDWR | O_CREAT, 0644);

	pr_info("tracker: module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	file_close();

	pr_info("tracker: module unloaded\n");
}
module_exit(fh_exit);
