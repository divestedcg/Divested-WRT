#!/bin/bash
#DivestOS: A privacy focused mobile distribution
#Copyright (c) 2017-2022 Divested Computing Group
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

#Upstream: https://gitlab.com/divested-mobile/divestos-build/-/blob/master/Scripts/Common/Functions.sh
#Use: hardenDefconfig "target/linux/generic/config-5.10"

hardenDefconfig() {
	#Attempts to enable/disable supported options to increase security
	#See https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
	#and (GPL-3.0) https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig_hardened_check/__init__.py

	local defconfigPath=$1;

	#Enable supported options
	#Linux <3.0
	declare -a optionsYes=("BUG" "DEBUG_CREDENTIALS" "DEBUG_KERNEL" "DEBUG_LIST" "DEBUG_NOTIFIERS" "DEBUG_RODATA" "DEBUG_SET_MODULE_RONX" "DEBUG_VIRTUAL" "IPV6_PRIVACY" "SECCOMP" "SECURITY" "SECURITY_DMESG_RESTRICT" "SLUB_DEBUG" "STRICT_DEVMEM" "SYN_COOKIES");
	optionsYes+=("DEBUG_SG"); #bootloops - https://patchwork.kernel.org/patch/8989981

	#Linux 3.4
	optionsYes+=("SECURITY_YAMA");

	#Linux 3.5
	optionsYes+=("PANIC_ON_OOPS" "SECCOMP_FILTER");

	#Linux 3.7
	optionsYes+=("SECURITY_YAMA_STACKED");

	#Linux 3.14
	optionsYes+=("CC_STACKPROTECTOR" "CC_STACKPROTECTOR_STRONG");

	#Linux 3.18
	optionsYes+=("HARDENED_USERCOPY" "SCHED_STACK_END_CHECK");

	#Linux 4.3
	optionsYes+=("ARM64_PAN" "CPU_SW_DOMAIN_PAN");

	#Linux 4.4
	optionsYes+=("LEGACY_VSYSCALL_NONE");

	#Linux 4.5
	optionsYes+=("IO_STRICT_DEVMEM");

	#Linux 4.6
	optionsYes+=("ARM64_UAO" "PAGE_POISONING" "PAGE_POISONING_ZERO" "PAGE_POISONING_NO_SANITY");

	#Linux 4.7
	optionsYes+=("RANDOMIZE_BASE" "SLAB_FREELIST_RANDOM");

	#Linux 4.8
	optionsYes+=("RANDOMIZE_MEMORY");

	#Linux 4.9
	optionsYes+=("THREAD_INFO_IN_TASK" "VMAP_STACK");

	#Linux 4.10
	optionsYes+=("ARM64_SW_TTBR0_PAN" "BUG_ON_DATA_CORRUPTION");

	#Linux 4.11
	optionsYes+=("STRICT_KERNEL_RWX" "STRICT_MODULE_RWX");

	#Linux 4.13
	optionsYes+=("FORTIFY_SOURCE" "REFCOUNT_FULL");

	#Linux 4.14
	optionsYes+=("SLAB_FREELIST_HARDENED");
	optionsYes+=("RESET_ATTACK_MITIGATION")

	#Linux 4.15
	optionsYes+=("PAGE_TABLE_ISOLATION" "RETPOLINE");

	#Linux 4.16
	optionsYes+=("UNMAP_KERNEL_AT_EL0");

	#Linux 4.17
	optionsYes+=("HARDEN_EL2_VECTORS");

	#Linux 4.18
	optionsYes+=("HARDEN_BRANCH_PREDICTOR" "STACKPROTECTOR" "STACKPROTECTOR_STRONG");

	#Linux 5.0
	optionsYes+=("ARM64_PTR_AUTH" "RODATA_FULL_DEFAULT_ENABLED" "STACKPROTECTOR_PER_TASK");

	#Linux 5.2
	optionsYes+=("INIT_STACK_ALL" "SHUFFLE_PAGE_ALLOCATOR");

	#Linux 5.3
	optionsYes+=("INIT_ON_ALLOC_DEFAULT_ON" "INIT_ON_FREE_DEFAULT_ON");

	#Linux 5.8
	optionsYes+=("ARM64_BTI_KERNEL" "DEBUG_WX");

	#Linux 5.9
	optionsYes+=("INIT_STACK_ALL_ZERO");

	#Linux 5.10
	optionsYes+=("ARM64_MTE");

	#Linux 5.13
	optionsYes+=("ARM64_EPAN" "RANDOMIZE_KSTACK_OFFSET_DEFAULT");

	#Linux 5.15
	optionsYes+=("IOMMU_DEFAULT_DMA_STRICT" "ZERO_CALL_USED_REGS");

	#Linux 5.17
	optionsYes+=("HARDEN_BRANCH_HISTORY" "MITIGATE_SPECTRE_BRANCH_HISTORY");

	#out of tree or renamed or removed ?
	optionsYes+=("MMC_SECDISCARD" "SECURITY_PERF_EVENTS_RESTRICT" "STRICT_MEMORY_RWX");

	for option in "${optionsYes[@]}"
	do
		#If the option is disabled, enable it
		sed -i 's/# CONFIG_'"$option"' is not set/CONFIG_'"$option"'=y/' $defconfigPath &>/dev/null || true;
		#If the option isn't present, add it enabled
		sed -zi '/CONFIG_'"$option"'=y/!s/$/\nCONFIG_'"$option"'=y/' $defconfigPath &>/dev/null || true;
	done

	#Disable supported options
	#Disabled: MSM_SMP2P_TEST, MAGIC_SYSRQ (breaks compile), KALLSYMS (breaks boot on select devices), IKCONFIG (breaks recovery), MSM_DLOAD_MODE (breaks compile), PROC_PAGE_MONITOR (breaks memory stats), SCHED_DEBUG (breaks compile), INET_DIAG
	declare -a optionsNo=("ACPI_APEI_EINJ" "ACPI_CUSTOM_METHOD" "ACPI_TABLE_UPGRADE" "BINFMT_AOUT" "BINFMT_MISC" "BLK_DEV_FD" "BT_HS" "CHECKPOINT_RESTORE" "COMPAT_BRK" "COMPAT_VDSO" "CP_ACCESS64" "DEBUG_KMEMLEAK" "DEVKMEM" "DEVMEM" "DEVPORT" "EARJACK_DEBUGGER" "FB_VIRTUAL" "HARDENED_USERCOPY_FALLBACK" "HARDENED_USERCOPY_PAGESPAN" "HIBERNATION" "HWPOISON_INJECT" "IA32_EMULATION" "IOMMU_NON_SECURE" "INPUT_EVBUG" "IO_URING" "IP_DCCP" "IP_SCTP" "KEXEC" "KEXEC_FILE" "KSM" "LDISC_AUTOLOAD" "LEGACY_PTYS" "LIVEPATCH" "MEM_SOFT_DIRTY" "MMIOTRACE" "MMIOTRACE_TEST" "MODIFY_LDT_SYSCALL" "NEEDS_SYSCALL_FOR_CMPXCHG" "NOTIFIER_ERROR_INJECTION" "OABI_COMPAT" "PAGE_OWNER" "PROC_KCORE" "PROC_VMCORE" "RDS" "RDS_TCP" "SECURITY_SELINUX_DISABLE" "SECURITY_WRITABLE_HOOKS" "SLAB_MERGE_DEFAULT" "STACKLEAK_METRICS" "STACKLEAK_RUNTIME_DISABLE" "TIMER_STATS" "TSC" "TSPP2" "UKSM" "UPROBES" "USELIB" "USERFAULTFD" "VIDEO_VIVID" "WLAN_FEATURE_MEMDUMP" "X86_IOPL_IOPERM" "X86_PTDUMP" "X86_VSYSCALL_EMULATION" "ZSMALLOC_STAT");
	optionsNo+=("FTRACE" "KPROBE_EVENTS" "UPROBE_EVENTS" "GENERIC_TRACER" "FUNCTION_TRACER" "STACK_TRACER" "HIST_TRIGGERS" "BLK_DEV_IO_TRACE" "FAIL_FUTEX");
	optionsNo+=("CORESIGHT" "DEBUG_ATOMIC_SLEEP" "DEBUG_BUS_VOTER" "DEBUG_MUTEXES" "DEBUG_PAGEALLOC" "DEBUG_STACK_USAGE" "DYNAMIC_DEBUG" "HAVE_DEBUG_BUGVERBOSE" "HAVE_DEBUG_KMEMLEAK" "IOMMU_DEBUG" "IOMMU_DEBUG_TRACKING" "IOMMU_TESTS" "L2TP_DEBUGFS" "LOCKUP_DETECTOR" "LOG_BUF_MAGIC" "PREEMPT_TRACER" "DEBUG_SPINLOCK");

	for option in "${optionsNo[@]}"
	do
		#If the option is enabled, disable it
		sed -i 's/CONFIG_'"$option"'=y/CONFIG_'"$option"'=n/' $defconfigPath &>/dev/null || true;
		#If the option isn't present, add it disabled
		sed -zi '/CONFIG_'"$option"'=n/!s/$/\nCONFIG_'"$option"'=n/' $defconfigPath &>/dev/null || true;
	done

	#Extras
	sed -i 's/CONFIG_ARCH_MMAP_RND_BITS=8/CONFIG_ARCH_MMAP_RND_BITS=16/' $defconfigPath &>/dev/null || true;
	sed -i 's/CONFIG_ARCH_MMAP_RND_BITS=18/CONFIG_ARCH_MMAP_RND_BITS=24/' $defconfigPath &>/dev/null || true;
	sed -i 's/CONFIG_DEFAULT_MMAP_MIN_ADDR=4096/CONFIG_DEFAULT_MMAP_MIN_ADDR=32768/' $defconfigPath &>/dev/null || true;
	sed -zi '/CONFIG_DEFAULT_MMAP_MIN_ADDR/!s/$/\nCONFIG_DEFAULT_MMAP_MIN_ADDR=32768/' $defconfigPath &>/dev/null || true;
	sed -i 's/CONFIG_LSM_MMAP_MIN_ADDR=4096/CONFIG_LSM_MMAP_MIN_ADDR=32768/' $defconfigPath &>/dev/null || true;
	sed -zi '/CONFIG_LSM_MMAP_MIN_ADDR/!s/$/\nCONFIG_LSM_MMAP_MIN_ADDR=32768/' $defconfigPath &>/dev/null || true;

	echo "Hardened defconfig for $1";
}
export -f hardenDefconfig;
