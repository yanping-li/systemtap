_KBUILD_CFLAGS := $(call flags,KBUILD_CFLAGS)
stap_check_gcc = $(shell  if $(CC) $(1) -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi)
CHECK_BUILD := $(CC) $(NOSTDINC_FLAGS) $(KBUILD_CPPFLAGS) $(CPPFLAGS) $(LINUXINCLUDE) $(_KBUILD_CFLAGS) $(CFLAGS_KERNEL) $(EXTRA_CFLAGS) $(CFLAGS) -DKBUILD_BASENAME=\"stap_2418\" -Werror -S -o /dev/null -xc 
stap_check_build = $(shell  if $(CHECK_BUILD) $(1) > /dev/null 2>&1 ; then echo "$(2)"; else echo "$(3)"; fi)
SYSTEMTAP_RUNTIME = "/usr/share/systemtap/runtime"
CONFIG_MODULE_SIG := n
EXTRA_CFLAGS :=
EXTRA_CFLAGS += -Iinclude2/asm/mach-default
EXTRA_CFLAGS += -I/lib/modules/3.10.0-514.el7.x86_64/build
STAPCONF_HEADER := /tmp/stapgGh85a/stapconf_001d2bb3414504e29684eac30d99c147_735.h
$(STAPCONF_HEADER):
	@> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-hrtimer-rel.c > /dev/null 2>&1; then echo "#define STAPCONF_HRTIMER_REL 1"; fi >> $@
	@echo "#define STAPCONF_HRTIMER_GET_RES 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-generated-compile.c > /dev/null 2>&1; then echo "#define STAPCONF_GENERATED_COMPILE 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-hrtimer-getset-expires.c > /dev/null 2>&1; then echo "#define STAPCONF_HRTIMER_GETSET_EXPIRES 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-inode-private.c > /dev/null 2>&1; then echo "#define STAPCONF_INODE_PRIVATE 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-constant-tsc.c > /dev/null 2>&1; then echo "#define STAPCONF_CONSTANT_TSC 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-ktime-get-real.c > /dev/null 2>&1; then echo "#define STAPCONF_KTIME_GET_REAL 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-x86-uniregs.c > /dev/null 2>&1; then echo "#define STAPCONF_X86_UNIREGS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-nameidata.c > /dev/null 2>&1; then echo "#define STAPCONF_NAMEIDATA_CLEANUP 1"; fi >> $@
	@echo "#define STAPCONF_UNREGISTER_KPROBES 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-kprobe-symbol-name.c > /dev/null 2>&1; then echo "#define STAPCONF_KPROBE_SYMBOL_NAME 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-real-parent.c > /dev/null 2>&1; then echo "#define STAPCONF_REAL_PARENT 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-uaccess.c > /dev/null 2>&1; then echo "#define STAPCONF_LINUX_UACCESS_H 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-oneachcpu-retry.c > /dev/null 2>&1; then echo "#define STAPCONF_ONEACHCPU_RETRY 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-dpath-path.c > /dev/null 2>&1; then echo "#define STAPCONF_DPATH_PATH 1"; fi >> $@
	@>> $@
	@>> $@
	@echo "#define STAPCONF_SYNCHRONIZE_SCHED 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-task-uid.c > /dev/null 2>&1; then echo "#define STAPCONF_TASK_UID 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-from_kuid_munged.c > /dev/null 2>&1; then echo "#define STAPCONF_FROM_KUID_MUNGED 1"; fi >> $@
	@>> $@
	@echo "#define STAPCONF_VM_AREA 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-procfs-owner.c > /dev/null 2>&1; then echo "#define STAPCONF_PROCFS_OWNER 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-alloc-percpu-align.c > /dev/null 2>&1; then echo "#define STAPCONF_ALLOC_PERCPU_ALIGN 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-x86-fs.c > /dev/null 2>&1; then echo "#define STAPCONF_X86_FS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-x86-xfs.c > /dev/null 2>&1; then echo "#define STAPCONF_X86_XFS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-x86-gs.c > /dev/null 2>&1; then echo "#define STAPCONF_X86_GS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-grsecurity.c > /dev/null 2>&1; then echo "#define STAPCONF_GRSECURITY 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-trace-printk.c > /dev/null 2>&1; then echo "#define STAPCONF_TRACE_PRINTK 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-regset.c > /dev/null 2>&1; then echo "#define STAPCONF_REGSET 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-utrace-regset.c > /dev/null 2>&1; then echo "#define STAPCONF_UTRACE_REGSET 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-uprobe-get-pc.c > /dev/null 2>&1; then echo "#define STAPCONF_UPROBE_GET_PC 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-hlist-4args.c > /dev/null 2>&1; then echo "#define STAPCONF_HLIST_4ARGS 1"; fi >> $@
	@echo "#define STAPCONF_TSC_KHZ 1">> $@
	@echo "#define STAPCONF_CPU_KHZ 1">> $@
	@echo "#define STAPCONF_MODULE_TEXT_ADDRESS 1">> $@
	@echo "#define STAPCONF_ADD_TIMER_ON 1">> $@
	@echo "#define STAPCONF_PROBE_KERNEL 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-hw_breakpoint_context.c > /dev/null 2>&1; then echo "#define STAPCONF_HW_BREAKPOINT_CONTEXT 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-save-stack-trace.c > /dev/null 2>&1; then echo "#define STAPCONF_KERNEL_STACKTRACE 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-save-stack-trace-no-bp.c > /dev/null 2>&1; then echo "#define STAPCONF_KERNEL_STACKTRACE_NO_BP 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-asm-syscall.c > /dev/null 2>&1; then echo "#define STAPCONF_ASM_SYSCALL_H 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-ring_buffer-flags.c > /dev/null 2>&1; then echo "#define STAPCONF_RING_BUFFER_FLAGS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-ring_buffer_lost_events.c > /dev/null 2>&1; then echo "#define STAPCONF_RING_BUFFER_LOST_EVENTS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-ring_buffer_read_prepare.c > /dev/null 2>&1; then echo "#define STAPCONF_RING_BUFFER_READ_PREPARE 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-kallsyms-on-each-symbol.c > /dev/null 2>&1; then echo "#define STAPCONF_KALLSYMS_ON_EACH_SYMBOL 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-walk-stack.c > /dev/null 2>&1; then echo "#define STAPCONF_WALK_STACK 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-stacktrace_ops-warning.c > /dev/null 2>&1; then echo "#define STAPCONF_STACKTRACE_OPS_WARNING 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-mm-context-vdso.c > /dev/null 2>&1; then echo "#define STAPCONF_MM_CONTEXT_VDSO 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-mm-context-vdso-base.c > /dev/null 2>&1; then echo "#define STAPCONF_MM_CONTEXT_VDSO_BASE 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-blk-types.c > /dev/null 2>&1; then echo "#define STAPCONF_BLK_TYPES 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-perf-structpid.c > /dev/null 2>&1; then echo "#define STAPCONF_PERF_STRUCTPID 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/perf_event_counter_context.c > /dev/null 2>&1; then echo "#define STAPCONF_PERF_COUNTER_CONTEXT 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/perf_probe_handler_nmi.c > /dev/null 2>&1; then echo "#define STAPCONF_PERF_HANDLER_NMI 1"; fi >> $@
	@>> $@
	@>> $@
	@echo "#define STAPCONF_VFS_PATH_LOOKUP 1">> $@
	@echo "#define STAPCONF_KERN_PATH 1">> $@
	@echo "#define STAPCONF_PROC_CREATE_DATA 1">> $@
	@echo "#define STAPCONF_PDE_DATA 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-module-sect-attrs.c > /dev/null 2>&1; then echo "#define STAPCONF_MODULE_SECT_ATTRS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-utrace-via-tracepoints.c > /dev/null 2>&1; then echo "#define STAPCONF_UTRACE_VIA_TRACEPOINTS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-task_work-struct.c > /dev/null 2>&1; then echo "#define STAPCONF_TASK_WORK_STRUCT 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-vm-area-pte.c > /dev/null 2>&1; then echo "#define STAPCONF_VM_AREA_PTE 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-relay-umode_t.c > /dev/null 2>&1; then echo "#define STAPCONF_RELAY_UMODE_T 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-fs_supers-hlist.c > /dev/null 2>&1; then echo "#define STAPCONF_FS_SUPERS_HLIST 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-compat_sigaction.c > /dev/null 2>&1; then echo "#define STAPCONF_COMPAT_SIGACTION 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-netfilter.c > /dev/null 2>&1; then echo "#define STAPCONF_NETFILTER_V313 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-netfilter-313b.c > /dev/null 2>&1; then echo "#define STAPCONF_NETFILTER_V313B 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-netfilter-4_1.c > /dev/null 2>&1; then echo "#define STAPCONF_NETFILTER_V41 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-netfilter-4_4.c > /dev/null 2>&1; then echo "#define STAPCONF_NETFILTER_V44 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-smpcall-5args.c > /dev/null 2>&1; then echo "#define STAPCONF_SMPCALL_5ARGS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-smpcall-4args.c > /dev/null 2>&1; then echo "#define STAPCONF_SMPCALL_4ARGS 1"; fi >> $@
	@echo "#define STAPCONF_CPU_CLOCK 1">> $@
	@echo "#define STAPCONF_LOCAL_CLOCK 1">> $@
	@echo "#define STAPCONF_UPROBE_REGISTER_EXPORTED 1">> $@
	@echo "#define STAPCONF_UPROBE_UNREGISTER_EXPORTED 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-old-inode-uprobes.c > /dev/null 2>&1; then echo "#define STAPCONF_OLD_INODE_UPROBES 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-inode-uretprobes.c > /dev/null 2>&1; then echo "#define STAPCONF_INODE_URETPROBES 1"; fi >> $@
	@>> $@
	@echo "#define STAPCONF_TASK_USER_REGSET_VIEW_EXPORTED 1">> $@
	@>> $@
	@>> $@
	@>> $@
	@>> $@
	@>> $@
	@>> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-pagefault_disable.c > /dev/null 2>&1; then echo "#define STAPCONF_PAGEFAULT_DISABLE 1"; fi >> $@
	@echo "#define STAPCONF_KALLSYMS 1">> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-uidgid.c > /dev/null 2>&1; then echo "#define STAPCONF_LINUX_UIDGID_H 1"; fi >> $@
	@echo "#define STAPCONF_SIGSET_FROM_COMPAT_EXPORTED 1">> $@
	@echo "#define STAPCONF_VZALLOC 1">> $@
	@echo "#define STAPCONF_VZALLOC_NODE 1">> $@
	@echo "#define STAPCONF_VMALLOC_NODE 1">> $@
	@>> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-tracepoint-strings.c > /dev/null 2>&1; then echo "#define STAPCONF_TRACEPOINT_STRINGS 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-timerfd.c > /dev/null 2>&1; then echo "#define STAPCONF_TIMERFD_H 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-module_layout.c > /dev/null 2>&1; then echo "#define STAPCONF_MODULE_LAYOUT 1"; fi >> $@
	@if $(CHECK_BUILD) $(SYSTEMTAP_RUNTIME)/linux/autoconf-mod_kallsyms.c > /dev/null 2>&1; then echo "#define STAPCONF_MOD_KALLSYMS 1"; fi >> $@
EXTRA_CFLAGS += -include $(STAPCONF_HEADER)
EXTRA_CFLAGS += -freorder-blocks
EXTRA_CFLAGS += -fasynchronous-unwind-tables
EXTRA_CFLAGS += $(call cc-option,-Wframe-larger-than=512)
EXTRA_CFLAGS += $(call cc-option,-fno-ipa-icf)
EXTRA_CFLAGS += -Wno-unused -Werror
EXTRA_CFLAGS += -I"/usr/share/systemtap/runtime"
obj-m := stap_2418.o
stap_2418-y :=  stap_2418_src.o stap_2418_aux_0.o
/tmp/stapgGh85a/stap_2418_src.c: $(STAPCONF_HEADER)
/tmp/stapgGh85a/stap_2418_aux_0.c: $(STAPCONF_HEADER)
