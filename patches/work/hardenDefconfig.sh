#!/bin/bash
#DivestOS: A mobile operating system divested from the norm.
#Copyright (c) 2017-2024 Divested Computing Group
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.

#Upstream: https://gitlab.com/divested-mobile/divestos-build/-/blob/master/Scripts/Common/Functions.sh
#Use: hardenDefconfig "target/linux/generic/config-6.12";

hardenDefconfig() {
	#Attempts to enable/disable supported options to increase security
	#See https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
	#and (GPL-3.0) https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig_hardened_check/__init__.py

	local defconfigPath="$1";

	#Enable supported options
	#Linux <3.0
	declare -a optionsYes=("BUG" "IPV6_PRIVACY" "SECCOMP" "SECURITY" "SECURITY_DMESG_RESTRICT" "STRICT_DEVMEM" "SYN_COOKIES");
	optionsYes+=("DEBUG_KERNEL" "DEBUG_CREDENTIALS" "DEBUG_LIST" "DEBUG_VIRTUAL");
	optionsYes+=("DEBUG_RODATA" "DEBUG_SET_MODULE_RONX");
	optionsYes+=("DEBUG_SG");
	optionsYes+=("DEBUG_NOTIFIERS");

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
	#optionsYes+=("LTO_CLANG" "CFI_CLANG");
	#optionsYes+=("RESET_ATTACK_MITIGATION"); #EFI only

	#Linux 4.15
	optionsYes+=("PAGE_TABLE_ISOLATION" "RETPOLINE");

	#Linux 4.16
	optionsYes+=("UNMAP_KERNEL_AT_EL0");

	#Linux 4.17
	optionsYes+=("HARDEN_EL2_VECTORS");

	#Linux 4.18
	optionsYes+=("HARDEN_BRANCH_PREDICTOR" "STACKPROTECTOR" "STACKPROTECTOR_STRONG");

	#Linux 5.0
	optionsYes+=("ARM64_PTR_AUTH"); #can stall CPUs on boot if missing support
	optionsYes+=("RODATA_FULL_DEFAULT_ENABLED" "STACKPROTECTOR_PER_TASK");

	#Linux 5.2
	optionsYes+=("INIT_STACK_ALL" "SHUFFLE_PAGE_ALLOCATOR");

	#Linux 5.8
	optionsYes+=("ARM64_BTI_KERNEL" "DEBUG_WX");

	#Linux 5.9
	optionsYes+=("INIT_STACK_ALL_ZERO");

	#Linux 5.10
	optionsYes+=("ARM64_MTE");

	#Linux 5.12
	#optionsYes+=("KFENCE"); #useless?

	#Linux 5.13
	optionsYes+=("ARM64_EPAN" "RANDOMIZE_KSTACK_OFFSET_DEFAULT");

	#Linux 5.15
	optionsYes+=("IOMMU_DEFAULT_DMA_STRICT" "ZERO_CALL_USED_REGS");
	#optionsYes+=("WERROR");

	#Linux 5.17
	optionsYes+=("HARDEN_BRANCH_HISTORY" "MITIGATE_SPECTRE_BRANCH_HISTORY");

	#Linux 5.18
	#optionsYes+=("SHADOW_CALL_STACK" "SHADOW_CALL_STACK_VMAP");

	optionsYes+=("INIT_ON_ALLOC_DEFAULT_ON" "INIT_ON_FREE_DEFAULT_ON");

	for option in "${optionsYes[@]}"
	do
		#If the option is disabled, enable it
		sed -i 's/# CONFIG_'"$option"' is not set/CONFIG_'"$option"'=y/' $defconfigPath &>/dev/null || true;
		if [[ "$1" != *"kernel/oneplus/msm8996"* ]] && [[ "$1" != *"kernel/xiaomi/msm8937"* ]]; then
			#If the option isn't present, add it enabled
			sed -zi '/CONFIG_'"$option"'=y/!s/$/\nCONFIG_'"$option"'=y/' $defconfigPath &>/dev/null || true;
		fi;
	done
	#Disable supported options
	#debugging
	declare -a optionsNo=("ACPI_APEI_EINJ" "ACPI_CUSTOM_METHOD" "ACPI_TABLE_UPGRADE");
	optionsNo+=("CHECKPOINT_RESTORE" "MEM_SOFT_DIRTY");
	optionsNo+=("CP_ACCESS64" "WLAN_FEATURE_MEMDUMP");
	optionsNo+=("DEVKMEM" "DEVMEM" "DEVPORT" "EARJACK_DEBUGGER" "PROC_KCORE" "PROC_VMCORE" "X86_PTDUMP");
	optionsNo+=("HWPOISON_INJECT" "NOTIFIER_ERROR_INJECTION");
	optionsNo+=("INPUT_EVBUG");
	optionsNo+=("LOG_BUF_MAGIC");
	optionsNo+=("L2TP_DEBUGFS");
	optionsNo+=("PAGE_OWNER");
	optionsNo+=("TIMER_STATS" "ZSMALLOC_STAT");
	optionsNo+=("UPROBES");
	optionsNo+=("SLUB_DEBUG" "SLUB_DEBUG_ON");
	optionsNo+=("STACKLEAK_METRICS" "STACKLEAK_RUNTIME_DISABLE"); #GCC only
	optionsNo+=("MMIOTRACE" "MMIOTRACE_TEST");
	optionsNo+=("IOMMU_DEBUG" "IOMMU_DEBUG_TRACKING" "IOMMU_NON_SECURE" "IOMMU_TESTS");
	optionsNo+=("DEBUG_ATOMIC_SLEEP" "DEBUG_BUS_VOTER" "DEBUG_MUTEXES" "DEBUG_KMEMLEAK" "DEBUG_PAGEALLOC" "DEBUG_STACK_USAGE" "DEBUG_SPINLOCK");
	#optionsNo+=("DEBUG_FS");
	optionsNo+=("FTRACE" "KPROBE_EVENTS" "UPROBE_EVENTS" "GENERIC_TRACER" "FUNCTION_TRACER" "STACK_TRACER" "HIST_TRIGGERS" "BLK_DEV_IO_TRACE" "FAIL_FUTEX" "DYNAMIC_DEBUG" "PREEMPT_TRACER");
	#legacy
	optionsNo+=("BINFMT_AOUT" "BINFMT_MISC");
	optionsNo+=("COMPAT_BRK" "COMPAT_VDSO");
	optionsNo+=("LDISC_AUTOLOAD" "LEGACY_PTYS");
	optionsNo+=("MODIFY_LDT_SYSCALL");
	optionsNo+=("OABI_COMPAT");
	optionsNo+=("USELIB");
	optionsNo+=("X86_IOPL_IOPERM" "X86_VSYSCALL_EMULATION");
	#unnecessary
	optionsNo+=("BLK_DEV_FD" "BT_HS" "IO_URING" "IP_DCCP" "IP_SCTP" "VIDEO_VIVID" "FB_VIRTUAL" "RDS" "RDS_TCP");
	optionsNo+=("HIBERNATION");
	optionsNo+=("KEXEC" "KEXEC_FILE");
	optionsNo+=("UKSM");
	optionsNo+=("KSM");
	optionsNo+=("LIVEPATCH");
	#unsafe
	optionsNo+=("HARDENED_USERCOPY_FALLBACK");
	optionsNo+=("SECURITY_SELINUX_DISABLE" "SECURITY_WRITABLE_HOOKS");
	optionsNo+=("SLAB_MERGE_DEFAULT");
	optionsNo+=("USERFAULTFD");
	#misc
	optionsNo+=("FB_MSM_MDSS_XLOG_DEBUG" "MSM_BUSPM_DEV" "MSMB_CAMERA_DEBUG" "MSM_CAMERA_DEBUG" "MSM_SMD_DEBUG");
	optionsNo+=("NEEDS_SYSCALL_FOR_CMPXCHG");
	optionsNo+=("TSC" "TSPP2");
	#breakage
	optionsNo+=("HARDENED_USERCOPY_PAGESPAN");

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
