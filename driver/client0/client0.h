/**********************************************************************
 * (c) Burluckij S.
 * e-mail: burluckij@gmail.com
 **********************************************************************/

#include "shared_data.h"

#define SECTION_ERROR		0x01
#define IMPORT_ERROR		0x02
#define EXPORT_ERROR		0x04
#define HEADER_ERROR		0x08
#define CRASH_INIT			0xFF
#define SUCCESS_INIT		0x00


#define INVALID_SET_FILE_POINTER		((DWORD)-1)
#define GET_HEADER(hModule)				(PCHAR)((PCHAR)hModule + (((PIMAGE_DOS_HEADER)hModule)->e_lfanew))
#define VALID_FILE(x)					((*((PWORD)x) == IMAGE_DOS_SIGNATURE) && ((*(PDWORD)GET_HEADER(x)) == IMAGE_NT_SIGNATURE))
#define	PAGE_MEM(x)						ExAllocatePool(PagedPool, x)
#define	NOPAGE_MEM(x)					ExAllocatePool(NonPagedPool, x)
#define NONPAGED_MEM(size)				ExAllocatePoolWithTag(NonPagedPool, size, 'stan');

#define INDEX_BY_ADDR(_Func)			*(PUCHAR)((PUCHAR)_Func + 1)
#define ADDR_BY_INDEX(_Func_Addr)		KeServiceDescriptorTable->ntoskrnl.ServiceTable[INDEX_BY_ADDR(_Func_Addr)]



typedef NTSTATUS
(NTAPI *PZwQuerySystemInformation) (
IN ULONG SystemInformationClass,
IN PVOID SystemInformation,
IN ULONG SystemInformationLength,
OUT PULONG ReturnLength
);

typedef NTSTATUS(*IrpHandler_Fn)(IN PDEVICE_OBJECT, IN PIRP);

#pragma pack(1)

typedef struct list_t_{
	PVOID pNext;
	PVOID pdata;
}list_t, *plist_t;

typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pdx;
	PUNICODE_STRING symlink_dev;
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// typedef struct _SYSTEM_SERVICE_TABLE
// {
// 	PNTPROC	ServiceTable; // array of pointers to the sys api
// 	PDWORD	CounterTable; // counter usage
// 	DWORD	ServiceLimit; // size of array
// 	PBYTE	ArgumentTable;
// }SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;
// 
// typedef struct _SERVICE_DESCRIPTOR_TABLE
// {
// 	SYSTEM_SERVICE_TABLE ntoskrnl; // system interface
// 	SYSTEM_SERVICE_TABLE win32k; // graphic interface
// 	SYSTEM_SERVICE_TABLE Table3;
// 	SYSTEM_SERVICE_TABLE Table4;
// 
// } SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

typedef struct _ProcessInfoStruct{
	ULONG	NextEntryDelta;
	ULONG	ThreadCount;
	ULONG	Reserved1[6];
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ProcessName;
	KPRIORITY	BasePriority;
	ULONG	ProcessId;
	ULONG	InheritedFromProcessId;
	ULONG	HandleCount;
	ULONG	Reserved2[2];
}ProcessInfo, *pProcessInfo;

typedef struct RTK_DATA_
{
	BYTE type;
	union
	{
		SSDT_HK ssdt;
		// iat_hk iat;
		// eat_hk eat;
	};
} RTK_DATA, *PRTK_DATA;

typedef struct dt_list
{
	PVOID pNext;
	PRTK_DATA pdt;
} dt_list, *pdt_list;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY			LoadOrder;
	LIST_ENTRY			MemoryOrder;
	LIST_ENTRY			InitializationOrder;
	PVOID				BaseAddress;
	PVOID				EntryPoint;
	ULONG				ImageSize;
	UNICODE_STRING		FullModuleName;
	UNICODE_STRING		ModuleName;
	ULONG				Flags;
	USHORT				LoadCount;
	USHORT				TlsIndex;

	union
	{
		LIST_ENTRY		Hash;

		struct
		{
			PVOID		SectionPointer;
			ULONG		CheckSum;
		};
	};

	ULONG				TimeStamp;
}
LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY LoadOrder;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	/*PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;*/
	PVOID ImageBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullModuleName;
	UNICODE_STRING ModuleName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
}
KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

#include <ntddk.h>



typedef struct _MMSECTION_FLAGS {
	/*0x000*/     UINT32       BeingDeleted : 1;
	/*0x000*/     UINT32       BeingCreated : 1;
	/*0x000*/     UINT32       BeingPurged : 1;
	/*0x000*/     UINT32       NoModifiedWriting : 1;
	/*0x000*/     UINT32       FailAllIo : 1;
	/*0x000*/     UINT32       Image : 1;
	/*0x000*/     UINT32       Based : 1;
	/*0x000*/     UINT32       File : 1;
	/*0x000*/     UINT32       Networked : 1;
	/*0x000*/     UINT32       NoCache : 1;
	/*0x000*/     UINT32       PhysicalMemory : 1;
	/*0x000*/     UINT32       CopyOnWrite : 1;
	/*0x000*/     UINT32       Reserve : 1;
	/*0x000*/     UINT32       Commit : 1;
	/*0x000*/     UINT32       FloppyMedia : 1;
	/*0x000*/     UINT32       WasPurged : 1;
	/*0x000*/     UINT32       UserReference : 1;
	/*0x000*/     UINT32       GlobalMemory : 1;
	/*0x000*/     UINT32       DeleteOnClose : 1;
	/*0x000*/     UINT32       FilePointerNull : 1;
	/*0x000*/     UINT32       DebugSymbolsLoaded : 1;
	/*0x000*/     UINT32       SetMappedFileIoComplete : 1;
	/*0x000*/     UINT32       CollidedFlush : 1;
	/*0x000*/     UINT32       NoChange : 1;
	/*0x000*/     UINT32       HadUserReference : 1;
	/*0x000*/     UINT32       ImageMappedInSystemSpace : 1;
	/*0x000*/     UINT32       UserWritable : 1;
	/*0x000*/     UINT32       Accessed : 1;
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;
	/*0x000*/     UINT32       Rom : 1;
	/*0x000*/     UINT32       filler : 2;
}MMSECTION_FLAGS, *PMMSECTION_FLAGS;


typedef struct _MMVAD_FLAGS {
	/*0x000*/     ULONG32      CommitCharge : 19;
	/*0x000*/     ULONG32      PhysicalMapping : 1;
	/*0x000*/     ULONG32      ImageMap : 1;
	/*0x000*/     ULONG32      UserPhysicalPages : 1;
	/*0x000*/     ULONG32      NoChange : 1;
	/*0x000*/     ULONG32      WriteWatch : 1;
	/*0x000*/     ULONG32      Protection : 5;
	/*0x000*/     ULONG32      LargePages : 1;
	/*0x000*/     ULONG32      MemCommit : 1;
	/*0x000*/     ULONG32      PrivateMemory : 1;
}MMVAD_FLAGS, *PMMVAD_FLAGS;

typedef struct _MMVAD_FLAGS2 {
	/*0x000*/     UINT32       FileOffset : 24;
	/*0x000*/     UINT32       SecNoChange : 1;
	/*0x000*/     UINT32       OneSecured : 1;
	/*0x000*/     UINT32       MultipleSecured : 1;
	/*0x000*/     UINT32       ReadOnly : 1;
	/*0x000*/     UINT32       LongVad : 1;
	/*0x000*/     UINT32       ExtendableFile : 1;
	/*0x000*/     UINT32       Inherit : 1;
	/*0x000*/     UINT32       CopyOnWrite : 1;
}MMVAD_FLAGS2, *PMMVAD_FLAGS2;

typedef struct CONTROL_AREA {
	/*0x000*/     struct _SEGMENT* Segment;
	/*0x004*/     struct _LIST_ENTRY DereferenceList;
	/*0x00C*/     ULONG32      NumberOfSectionReferences;
	/*0x010*/     ULONG32      NumberOfPfnReferences;
	/*0x014*/     ULONG32      NumberOfMappedViews;
	/*0x018*/     UINT16       NumberOfSubsections;
	/*0x01A*/     UINT16       FlushInProgressCount;
	/*0x01C*/     ULONG32      NumberOfUserReferences;
	union
	{
		/*0x020*/         ULONG32      LongFlags;
		/*0x020*/         struct _MMSECTION_FLAGS Flags;
	}u;
	/*0x024*/     struct _FILE_OBJECT* FilePointer;
	/*0x028*/     struct _EVENT_COUNTER* WaitingForDeletion;
	/*0x02C*/     UINT16       ModifiedWriteCount;
	/*0x02E*/     UINT16       NumberOfSystemCacheViews;
}CONTROL_AREA, *PCONTROL_AREA;


typedef struct MMVAD {
	/*0x000*/     ULONG32      StartingVpn;
	/*0x004*/     ULONG32      EndingVpn;
	/*0x008*/     struct _MMVAD* Parent;
	/*0x00C*/     struct _MMVAD* LeftChild;
	/*0x010*/     struct _MMVAD* RightChild;
	union
	{
		/*0x014*/         ULONG32      LongFlags;
		/*0x014*/         struct _MMVAD_FLAGS VadFlags;
	}u;
	/*0x018*/     struct _CONTROL_AREA* ControlArea;
	/*0x01C*/     struct _MMPTE* FirstPrototypePte;
	/*0x020*/     struct _MMPTE* LastContiguousPte;
	union
	{
		/*0x024*/         ULONG32      LongFlags2;
		/*0x024*/         struct _MMVAD_FLAGS2 VadFlags2;
	}u2;
}MMVAD, *PMMVAD;

#pragma pack()


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////


EXTERN_C void List_Vad();
EXTERN_C NTSTATUS DriverDispatchControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
