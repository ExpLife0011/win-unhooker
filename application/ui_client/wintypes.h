
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#ifndef _WINDOWS_
#include <windows.h>
#endif

#ifndef CBASE_H
#include "CBase.h"
#endif

#define MAXIMUM_FILENAME_LENGTH 255
#define VS_ERROR				-1
#define VS_SUCCESS			0
//#define __in
//#define __out


typedef LONG KPRIORITY;
typedef LONG NTSTATUS;

#define STATUS_SUCCESS	((NTSTATUS)0x00000000L)

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SYSTEM_MODULE {
	ULONG Reserved1;
	ULONG Reserved2;
	PVOID ImageBaseAddress;
	ULONG ImageSize;
	ULONG Flags;
	WORD Id;
	WORD Rank;
	WORD w018;
	WORD NameOffset;
	BYTE Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId; // PID
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SpareUl2;
	ULONG SpareUl3;
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG QuotaPeakPagedPoolUsage;
	ULONG QuotaPagedPoolUsage;
	ULONG QuotaPeakNonPagedPoolUsage;
	ULONG QuotaNonPagedPoolUsage;
	ULONG PagefileUsage;
	ULONG PeakPagefileUsage;
	ULONG PrivatePageCount;
	SYSTEM_THREAD_INFORMATION TH[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// Describes a module in a some context
typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;				// Pointers to previous and next LDR_MODULE in load order
	LIST_ENTRY InMemoryOrderModuleList;				// Pointers to previous and next LDR_MODULE in memory placement order
	LIST_ENTRY InInitializationOrderModuleList;		// Pointers to previous and next LDR_MODULE in initialization order
	PVOID BaseAddress;								// Module base address known also as HMODULE
	PVOID EntryPoint;								// Module entry point (address of initialization procedure)
	ULONG SizeOfImage;								// Sum of all image's sections placed in memory. Rounded up to 4Kb (page size)
	UNICODE_STRING FullDllName;						// Path and name of module
	UNICODE_STRING BaseDllName;						// Module name only
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;						// Pointer to LdrpHashTable
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BYTE Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// Short description of the structure
typedef struct _PEB {
	BYTE InheritedAddressSpace;
	BYTE ReadImageFileExecOptions;
	BYTE BeingDebugged;
	BYTE SpareBool;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA LdrData;
	// ...

} PEB, *PPEB;

// Full description of the original structure

// typedef struct _PEB {
// 	BOOLEAN                 InheritedAddressSpace;
// 	BOOLEAN                 ReadImageFileExecOptions;
// 	BOOLEAN                 BeingDebugged;
// 	BOOLEAN                 Spare;
// 	HANDLE                  Mutant;
// 	PVOID                   ImageBaseAddress;
// 	PPEB_LDR_DATA           LoaderData;
// 	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
// 	PVOID                   SubSystemData;
// 	PVOID                   ProcessHeap;
// 	PVOID                   FastPebLock;
// 	PPEBLOCKROUTINE         FastPebLockRoutine;
// 	PPEBLOCKROUTINE         FastPebUnlockRoutine;
// 	ULONG                   EnvironmentUpdateCount;
// 	PPVOID                  KernelCallbackTable;
// 	PVOID                   EventLogSection;
// 	PVOID                   EventLog;
// 	PPEB_FREE_BLOCK         FreeList;
// 	ULONG                   TlsExpansionCounter;
// 	PVOID                   TlsBitmap;
// 	ULONG                   TlsBitmapBits[0x2];
// 	PVOID                   ReadOnlySharedMemoryBase;
// 	PVOID                   ReadOnlySharedMemoryHeap;
// 	PPVOID                  ReadOnlyStaticServerData;
// 	PVOID                   AnsiCodePageData;
// 	PVOID                   OemCodePageData;
// 	PVOID                   UnicodeCaseTableData;
// 	ULONG                   NumberOfProcessors;
// 	ULONG                   NtGlobalFlag;
// 	BYTE                    Spare2[0x4];
// 	LARGE_INTEGER           CriticalSectionTimeout;
// 	ULONG                   HeapSegmentReserve;
// 	ULONG                   HeapSegmentCommit;
// 	ULONG                   HeapDeCommitTotalFreeThreshold;
// 	ULONG                   HeapDeCommitFreeBlockThreshold;
// 	ULONG                   NumberOfHeaps;
// 	ULONG                   MaximumNumberOfHeaps;
// 	PPVOID                  *ProcessHeaps;
// 	PVOID                   GdiSharedHandleTable;
// 	PVOID                   ProcessStarterHelper;
// 	PVOID                   GdiDCAttributeList;
// 	PVOID                   LoaderLock;
// 	ULONG                   OSMajorVersion;
// 	ULONG                   OSMinorVersion;
// 	ULONG                   OSBuildNumber;
// 	ULONG                   OSPlatformId;
// 	ULONG                   ImageSubSystem;
// 	ULONG                   ImageSubSystemMajorVersion;
// 	ULONG                   ImageSubSystemMinorVersion;
// 	ULONG                   GdiHandleBuffer[0x22];
// 	ULONG                   PostProcessInitRoutine;
// 	ULONG                   TlsExpansionBitmap;
// 	BYTE                    TlsExpansionBitmapBits[0x80];
// 	ULONG                   SessionId;
// } PEB, *PPE

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26
} PROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemPowerInformation_,/* new  */
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation

} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef LONG (WINAPI *FPFN_NtQuerySystemInformation)(ULONG SystemInformationCLass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS (WINAPI *FPFN_NtQueryInformationProcess) (
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
