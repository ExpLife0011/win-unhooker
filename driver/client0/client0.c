/**********************************************************************
 * (c) Vsoft Lab
 * e-mail: burluckij@gmail.com
 **********************************************************************/

#include "Ntifs.h"
#include "ntddk.h"
#include "ntdef.h"
#include "stdio.h"
#include "stdlib.h"

#include "client0.h"
#include "w32.h"
#include "ntt.h"
#include "kstr.h"
#include "list_t.h"
#include "algo_t.h"

#define CL0_VERSION				100
#define SEC_IMAGE				0x1000000
#define GET_MAX_POINT(n)		(n>0?n-1:0)
#define BUILD_RESPONSE(X, Y)	(memcpy(X, Y, sizeof(CL0_REQUEST)))
#define DRIVER_IS_CONFIGURED	\
if (gDriverIsConfigured == FALSE){ goto DRIVER_UNPREPARED; }


extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;
extern PWORD NtBuildNumber;
extern POBJECT_TYPE* IoDeviceObjectType;
extern NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
IN PUNICODE_STRING ObjectPath,
IN ULONG Attributes,
IN PACCESS_STATE PassedAccessState OPTIONAL,
IN ACCESS_MASK DesiredAccess OPTIONAL,
IN POBJECT_TYPE ObjectType,
IN KPROCESSOR_MODE AccessMode,
IN OUT PVOID ParseContext OPTIONAL,
OUT PVOID *ObjectPtr
);

/* System offsets. */
ULONG off_EPROCESS_ActiveProcessLink = 0;
ULONG off_EPROCESS_ProcessName = 0;
ULONG off_EPROCESS_PID = 0;
ULONG off_EPROCESS_RootVad = 0;

PDRIVER_OBJECT g_clientDrvObj = NULL;
PDEVICE_OBJECT g_clientDevObj = NULL;

UNICODE_STRING	deviceNameUnicodeString;
UNICODE_STRING	deviceLinkUnicodeString;

PZwQuerySystemInformation sysapi_ZwQuerySystemInformation;

/* Address of windows kernel module in memory */
PVOID g_ntoskrnl_addr = 0;
ULONG g_SDT_offset_ntoskrnl = 0;
PSERVICE_DESCRIPTOR_TABLE g_ptrSDT = NULL;

// Default stub for uninitialized DriverObject->MajorFunction[IRP_MJ_Xxx]
ULONG g_IrpHandlerStub = 0;

/* Associated with kernel mapping. */
HANDLE g_hKernelFile = 0;
HANDLE g_hKernelSection = 0;
PVOID g_kernel_mapped_addr = 0;

ANSI_STRING gKrnlFilePath;
UNICODE_STRING gwKrnlFilePath;

EXE_FILE g_ExeNtoskernl;
EXE_FILE g_kernel_mapped_file;

static BOOL gDriverIsConfigured = FALSE;

void FreeMemory(PVOID p)
{
	if (p){
		ExFreePool(p);
	}
}

DWORD RemoveWP(__out KIRQL* pOldIRQL)
{
	DWORD OldCR0;

	*pOldIRQL = KeRaiseIrqlToDpcLevel();

	_asm {
		mov eax, CR0
			mov OldCR0, eax
			and eax, 0xFFFEFFFF
			mov cr0, eax
	}

	return OldCR0;
}

VOID ResetWP(__in DWORD OldCR0, __in KIRQL OldIRQL)
{
	_asm {
		mov eax, OldCR0
		mov cr0, eax
	}

	KeLowerIrql(OldIRQL);
}

ULONG LoadFile(WCHAR * name, ULONG fileSize, __out HANDLE* phFile, __out HANDLE* phMap)
{
	ULONG mappedAddr = 0;

	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK io;
	UNICODE_STRING FileName;
	LARGE_INTEGER MaxSize;
	ULONG ViewSize;

	//ViewSize = fileSize;
	//MaxSize.LowPart = fileSize;
	//MaxSize.HighPart = 0;
	ViewSize = fileSize;
	MaxSize.LowPart = fileSize;
	MaxSize.HighPart = 0;

	RtlInitUnicodeString(&FileName, name);

	InitializeObjectAttributes(&oa, &FileName, OBJ_CASE_INSENSITIVE /*OBJ_KERNEL_HANDLE*/, 0, 0);

	NTSTATUS opened = ZwCreateFile(phFile /*ghKernelFile*/,
		GENERIC_READ,
		&oa,
		&io,
		0,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		0,
		0,
		0);

	if (opened  == STATUS_SUCCESS)
	{
		NTSTATUS created = ZwCreateSection(phMap,
			SECTION_MAP_READ,
			0,
			&MaxSize,
			PAGE_READONLY /*PAGE_READWRITE*/,
			/*SEC_COMMIT*/ SEC_IMAGE,
			*phFile);

		if (created == STATUS_SUCCESS)
		{
			NTSTATUS mapped = ZwMapViewOfSection(*phMap,
				ZwCurrentProcess(),
				(PVOID*)&mappedAddr,
				0,
				fileSize,
				0,
				&ViewSize,
				ViewUnmap,
				/*MEM_RESERVE*/0,
				PAGE_READONLY /*PAGE_READWRITE*/);

			if (!NT_SUCCESS(mapped))
			{
				DbgPrint("\nZwMapViewOfSection failed! %x\n", mapped);
				ZwClose(*phMap);
				ZwClose(*phFile);
				mappedAddr = 0;
			} else {
				DbgPrint("cl0: %ws mapped size %d", name, ViewSize);
			}
		} else {
			DbgPrint("\ncl0: ZwCreateSection failed! code %x\n", created);
			ZwClose(*phFile);
		}

	} else {
		 DbgPrint("\ncl0: ZwCreateFile failed! %d(0x%x) \n", opened, opened);
	}

	return mappedAddr;
}

DWORD getCountOfProcesses(PSYSTEM_PROCESS_INFORMATION phead)
{
	DWORD count = 0;

	// while(phead->NextEntryOffset)
	do
	{
		phead = (PSYSTEM_PROCESS_INFORMATION)((DWORD)phead + phead->NextEntryOffset);
		count++;
	} while (phead->NextEntryOffset);

	return count;
}

// Returns STATUS_SUCCESS if success otherwise STATUS_BUFFER_TOO_SMALL
// and saves required size in pSize
NTSTATUS GetLoadedProcesses(PDWORD pSize, PCHAR pBuf)
{
	ulong reqLength = 0;
	PSYSTEM_PROCESS_INFORMATION pproc = NULL, pentry = NULL;

	sysapi_ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &reqLength);

	if ((pproc = (PSYSTEM_PROCESS_INFORMATION)PAGE_MEM(reqLength)))
	{
		if (sysapi_ZwQuerySystemInformation(SystemProcessInformation, pproc, reqLength, &reqLength) == STATUS_SUCCESS)
		{
			DWORD count_of_processes = getCountOfProcesses(pproc);
			//DbgPrint("client0: processes running %d\n", count_of_processes);
			DWORD requiredSize = sizeof(CL0_PROC_INFO) * count_of_processes;

			//DbgPrint("client0: GetLoadedProcesses required size %d\n", requiredSize);

			if ((*pSize) < requiredSize)
			{
				*pSize = requiredSize;
				ExFreePool(pproc);
				return STATUS_BUFFER_TOO_SMALL;
			}

			*pSize = requiredSize;

			PCL0_PROC_INFO pOutInfo = (PCL0_PROC_INFO)pBuf;
			pentry = pproc;
			for (ulong i = 0; i < count_of_processes; i++, pOutInfo++)
			{
				ANSI_STRING procname;
				RtlUnicodeStringToAnsiString(&procname, &pentry->ImageName, TRUE);
				pOutInfo->fileName[0] = '\0';
				kstrcpy(pOutInfo->fileName, procname.Buffer);
				pOutInfo->pid = (DWORD)pentry->UniqueProcessId;

				// !!!!!!! for test 
				// DbgPrint("GET_PROC: %s\n", pOutInfo->fileName);
				RtlFreeAnsiString(&procname);

				pentry = (PSYSTEM_PROCESS_INFORMATION)((DWORD)pentry + pentry->NextEntryOffset);
			}
		} 

		ExFreePool(pproc);
	}

	return STATUS_SUCCESS;
}

// Returns STATUS_SUCCESS if success otherwise STATUS_BUFFER_TOO_SMALL
// and saves required size in pSize
NTSTATUS GetLoadedSysModules(PDWORD pSize, PCHAR pBuf)
{
	ulong reqLength = 0;
	PSYSTEM_MODULE_INFORMATION pmod_inf = NULL;

	sysapi_ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &reqLength);

	if ((pmod_inf = (PSYSTEM_MODULE_INFORMATION)PAGE_MEM(reqLength)))
	{
		if (sysapi_ZwQuerySystemInformation(SystemModuleInformation, pmod_inf, reqLength, &reqLength) == STATUS_SUCCESS)
		{
			DWORD requiredSize = pmod_inf->ModulesCount * sizeof(CL0_KRNL_MODULE);

			//DbgPrint("client0: GetLoadedSysModules required size %d", requiredSize);

			if (*pSize < requiredSize)
			{
				*pSize = requiredSize;
				ExFreePool(pmod_inf);
				return STATUS_BUFFER_TOO_SMALL;
			}

			*pSize = requiredSize;

			PCL0_KRNL_MODULE pOutInfo = (PCL0_KRNL_MODULE)pBuf;
			for (ulong i = 0; i < pmod_inf->ModulesCount; i++, pOutInfo++)
			{

				pOutInfo->imageBase = (DWORD)pmod_inf->Modules[i].ImageBaseAddress;
				pOutInfo->size = pmod_inf->Modules[i].ImageSize;
				memcpy(pOutInfo->fileName, pmod_inf->Modules[i].Name, kstrlen(pmod_inf->Modules[i].Name) + 1);
				//kstrcpy(pOutInfo->fileName, pmod_inf->Modules[i].Name);
			}
		}

		ExFreePool(pmod_inf);
	}

	return STATUS_SUCCESS;
}

PVOID GetDrvImageBase(__in const char* szKrnlName)
{
	PVOID pImageBase = NULL;
	DWORD requiredSize = 0;

	GetLoadedSysModules(&requiredSize, 0);

	PCL0_KRNL_MODULE psysmodules = (PCL0_KRNL_MODULE)PAGE_MEM(requiredSize);

	if (psysmodules)
	{
		if (GetLoadedSysModules(&requiredSize, (PCHAR)psysmodules) == STATUS_SUCCESS)
		{
			for (PCL0_KRNL_MODULE pmod = psysmodules; pmod != psysmodules + (requiredSize / sizeof(CL0_KRNL_MODULE)); ++pmod)
			{
				if (kstrstr(pmod->fileName, szKrnlName) != NULL)
				{
					pImageBase = (PVOID)pmod->imageBase;
					break;
				}
			}
		}

		ExFreePool(psysmodules);
	}

	return pImageBase;
}

PVOID GetImageBaseByPointer(PVOID p)
{
	PVOID pImageBase = NULL;
	DWORD requiredSize = 0;

	GetLoadedSysModules(&requiredSize, 0);

	PCL0_KRNL_MODULE psysmodules = (PCL0_KRNL_MODULE)PAGE_MEM(requiredSize);

	if (psysmodules)
	{
		if (GetLoadedSysModules(&requiredSize, (PCHAR)psysmodules) == STATUS_SUCCESS)
		{
			for (PCL0_KRNL_MODULE pmod = psysmodules; pmod != psysmodules + (requiredSize / sizeof(CL0_KRNL_MODULE)); ++pmod)
			{
				if ((DWORD)p >= (DWORD)pmod->imageBase && (DWORD)p <= ((DWORD)pmod->imageBase + pmod->size))
				{
					pImageBase = (PVOID)pmod->imageBase;
					break;
				}
			}
		}

		ExFreePool(psysmodules);
	}

	return pImageBase;
}

// Returns module name by its ImageBase address
// In pDest writes full file path, for example c:\windows\system32\somedrv.sys
// pLength contains sizeof of string, including last zero symbol
BOOLEAN GetModuleName(PVOID pImageBase, PVOID pDest, PDWORD plength)
{
	BOOLEAN result = FALSE;
	DWORD requiredSize = 0;

	GetLoadedSysModules(&requiredSize, 0);

	PCL0_KRNL_MODULE psysmodules = (PCL0_KRNL_MODULE)PAGE_MEM(requiredSize);

	if (psysmodules)
	{
		if (GetLoadedSysModules(&requiredSize, (PCHAR)psysmodules) == STATUS_SUCCESS)
		{
			for (PCL0_KRNL_MODULE pmod = psysmodules; pmod != psysmodules + (requiredSize / sizeof(CL0_KRNL_MODULE)); ++pmod)
			{
				if (pImageBase == (PVOID)pmod->imageBase)
				{
					DWORD mod_name_size = strlen((char*)pmod->fileName) + 1;

					if (mod_name_size <= *plength)
					{
						memcpy((PVOID)pDest, (PCHAR)pmod->fileName, mod_name_size);
						result = TRUE;
					}

					*plength = mod_name_size;
					break;
				}
			}
		}

		ExFreePool(psysmodules);
	}

	return result;
}

// Seeks interceptions in system services descriptor table
// ! should implement definition name of intercepted service
list_t* LookupSsdtHooks(PDWORD pLength)
{
	DWORD iLimit = KeServiceDescriptorTable->ntoskrnl.ServiceLimit;
	PVOID pFirstAddrRegion = g_ExeNtoskernl.m_base_x;
	PVOID pEndAddrRegion = (PCHAR)pFirstAddrRegion + g_ExeNtoskernl.m_pImageNtHeader->OptionalHeader.SizeOfImage;
	PVOID pfn = NULL;
	DWORD dwLength = 260;
	PCHAR modname = (PCHAR)PAGE_MEM(260);
	BOOLEAN found_filename = FALSE;
	list_t* hooksInfo = NULL;

	// default system is 'clean'
	*pLength = 0;

	DbgPrint("client0: LookupSsdtHooks; pEnd %x srvcnt %d\n", pEndAddrRegion, iLimit);

	for (DWORD iCounter = 0; iCounter < iLimit; iCounter++)
	{
		pfn = (PVOID)KeServiceDescriptorTable->ntoskrnl.ServiceTable[iCounter];
		if (pfn)
		{
			// 1. Compare with original addresses from disk
			// ...


			// 2. It's the second way to do the same things
			// Hook is found only if its address doesn't belong to kernel memory region

			// Does the address belong to the kernel module?
			if (!((PCHAR)pfn >= (PCHAR)pFirstAddrRegion && (PCHAR)pfn <= (PCHAR)pEndAddrRegion))
			{
				if (!hooksInfo){
					hooksInfo = list_create();
				}

				PVOID rootkit_imagebase = GetImageBaseByPointer(pfn);

				// Collects information about interceptor
				found_filename = GetModuleName(rootkit_imagebase, modname, &dwLength);

				if (!found_filename)
				{
					kstrcpy(modname, "hidden!file_not_found!");
				}

				SSDT_HK* hooked_serv = PAGE_MEM(sizeof(SSDT_HK));

				hooked_serv->index = iCounter;
				hooked_serv->hookproc = pfn;
				hooked_serv->rtkimage = rootkit_imagebase;
				memcpy(hooked_serv->rtkfile, modname, kstrlen(modname)+1);

				// Save information about interception
				list_insert(hooksInfo, hooked_serv);
				(*pLength)++;

				DbgPrint("client0: interceptor was found in ssdt [%x]=%x  %s %x\n",
					iCounter,
					pfn,
					hooked_serv->rtkfile,
					rootkit_imagebase);
			}
		}
	}

	ExFreePool(modname);
	return hooksInfo;
}

void RemoveHookInSdt(__in DWORD index /* one of indexes from system services */ )
{
	DWORD OldCR0;
	DWORD offset_to_original_fn = 0, addr_original_fn = 0, hook_fn = 0;
	PVOID pServicesTable = ( ((PUCHAR)g_ntoskrnl_addr) + g_SDT_offset_ntoskrnl);
	PDWORD pCurrPtrToFn = (PDWORD)( ((PUCHAR)pServicesTable) + index * sizeof(DWORD));
	PDWORD pOrigPtrToFn = (PDWORD)( ((PUCHAR)g_kernel_mapped_addr) + g_SDT_offset_ntoskrnl + index * sizeof(DWORD));

	offset_to_original_fn = *pOrigPtrToFn - g_kernel_mapped_file.m_pImageNtHeader->OptionalHeader.ImageBase;
	addr_original_fn = (DWORD)g_ntoskrnl_addr + offset_to_original_fn;

	// Exchange pointers
	KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

	_asm {
		mov eax, CR0
		mov OldCR0, eax
		and eax, 0xFFFEFFFF
		mov cr0, eax
	}

	hook_fn = *pCurrPtrToFn;
	*pCurrPtrToFn = addr_original_fn;

	_asm {
		mov eax, OldCR0
		mov cr0, eax
	}

	KeLowerIrql(oldIrql);

	DbgPrint("cl0: exchange ptrs hook_proc=%x  original_fn=%x (offs. %x)\n",
		hook_fn,
		addr_original_fn,
		offset_to_original_fn);
}

// Retrievals information from IA32_SYSENTER_EIP register
ULONG SysenterHandler()
{
	ULONG sysenter_handler = 0;

	__asm {
		mov ecx, 0x176
		rdmsr
		mov sysenter_handler, eax
	}

	return sysenter_handler;
}

// The function changes value of IA32_SYSENTER_EIP register
ULONG SysenterExchange(ULONG new_handler)
{
	ULONG old_handler;

	__asm {
		mov ecx, 0x176
		rdmsr
		mov old_handler, eax
		mov eax, new_handler
		wrmsr
	}

	return old_handler;
}

/* Provides information about sysenter handler. Original handler it's 'ntoskrnl.exe'. */
void LookupSysenterHook(__out SYSENTER_HANDLER* handler_inf)
{
	PVOID pfn = (PVOID)SysenterHandler();
	PVOID pkrnl = g_ntoskrnl_addr;
	ULONG krnlsize = g_ExeNtoskernl.m_pImageNtHeader->OptionalHeader.SizeOfImage;

	handler_inf->hooked = !((pkrnl >= pfn) && ((ULONG)pfn <= (ULONG)pkrnl + krnlsize));
	handler_inf->handler = pfn;
	handler_inf->imagebase = GetImageBaseByPointer(pfn);
}

/* Not implemented. */
BOOLEAN ResetSysenter()
{
	//
	return FALSE;
}

//	drv_name could be = L"\\Device\\Tcp"
PDEVICE_OBJECT GetDeviceObject(__in WCHAR* dev_name, __out PFILE_OBJECT* pfile)
{
	NTSTATUS       ntStatus;
	UNICODE_STRING device_name;
	PDEVICE_OBJECT pDevice = NULL;

	RtlInitUnicodeString(&device_name, dev_name);
	ntStatus = IoGetDeviceObjectPointer(&device_name, FILE_READ_DATA /*STANDARD_RIGHTS_READ*/, pfile, &pDevice);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("cl0: IoGetDeviceObjectPointer failed, NTSTATUS = %d (0x%x)\n",
			ntStatus,
			ntStatus);

		return NULL;
	}

	// if (pfile != NULL) ObDereferenceObject(*pfile);
	return pDevice;
}

/* Returns the highest device in device hierarchy*/
/* Similar to IoGetAttachedDeviceReference */
PDEVICE_OBJECT GetHighestDevice(__in PDEVICE_OBJECT deviceObject)
{
	PDEVICE_OBJECT pHighestDevice = deviceObject;

	while (pHighestDevice->AttachedDevice)
	{
		pHighestDevice = pHighestDevice->AttachedDevice;
	}

	return pHighestDevice;
}

/* Returns the lowest device in device hierarchy */
PDEVICE_OBJECT GetLowestDevice(__in PDEVICE_OBJECT DeviceObject)
{
	PDEVICE_OBJECT pLowestDevice = DeviceObject;

	// Get access to list dev list
	KIRQL irql = KeAcquireQueuedSpinLock(LockQueueIoDatabaseLock);
	PDEVOBJ_EXTENSION deviceExtension = pLowestDevice->DeviceObjectExtension;

	/* Keep going as long as we're attached */
	while (deviceExtension->AttachedTo)
	{
		/* Gets the lowest device and its extension */
		pLowestDevice = deviceExtension->AttachedTo;
		deviceExtension = pLowestDevice->DeviceObjectExtension;
	}

	KeReleaseQueuedSpinLock(LockQueueIoDatabaseLock, irql);
	return pLowestDevice;
}

/* Note: This procedure allocates memory for pObjName. User should free memory after call. */
NTSTATUS GetObjectName(__in PVOID pObject, __out PUNICODE_STRING* pObjName)
{
	DWORD required_size = 0;
	POBJECT_NAME_INFORMATION poni = NULL;
	NTSTATUS status = ObQueryNameString(pObject, NULL, 0, &required_size);

	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		PVOID buffer = NONPAGED_MEM(required_size);
		if (buffer)
		{
			poni = (POBJECT_NAME_INFORMATION)buffer;
			RtlZeroMemory(buffer, required_size);
			poni->Name.MaximumLength = required_size - sizeof(OBJECT_NAME_INFORMATION);

			status = ObQueryNameString(pObject, poni, required_size, &required_size);
			if (!NT_SUCCESS(status))
			{
				FreeMemory(buffer);
			}
			else
			{
				/* Changes pointer in following cases:
				1. Memory was allocated successfully.
				2. Object's name was found.
				*/
				*pObjName = (PUNICODE_STRING)poni;
			}
		}
		else {
			status = STATUS_NO_MEMORY;
		}
	}

	return status;
}

/* notes: use locks and non_paged memory */ 
void GetDriverObjectInfo(__in PDRIVER_OBJECT pDriverObject, __out PDRIVER_OBJECT_INFO pDriverObjInfo)
{
	PUNICODE_STRING pObjName = NULL;
	PKLDR_DATA_TABLE_ENTRY pldr_drv = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;

	if (!pldr_drv){
		return;
	}

	memset(pDriverObjInfo, 0, sizeof(DRIVER_OBJECT_INFO));

	pDriverObjInfo->driver_module.pImageBase = pldr_drv->ImageBase;
	pDriverObjInfo->driver_module.ImageSize = pldr_drv->SizeOfImage;
	pDriverObjInfo->driver_module.pEntryPoint = pldr_drv->EntryPoint;

	// image.filePath
	if (pldr_drv->FullModuleName.Length < sizeof(pDriverObjInfo->driver_module.filePath)){
		memcpy(pDriverObjInfo->driver_module.filePath,
			pldr_drv->FullModuleName.Buffer,
			pldr_drv->FullModuleName.Length);
	}

	// image.fileName
	if (pldr_drv->ModuleName.Length < sizeof(pDriverObjInfo->driver_module.fileName)){
		memcpy(pDriverObjInfo->driver_module.fileName,
			pldr_drv->ModuleName.Buffer,
			pldr_drv->ModuleName.Length);
	}

	// .driver_name
	if (pDriverObject->DriverName.Length < sizeof(pDriverObjInfo->driver_name)){
		memcpy(pDriverObjInfo->driver_name,
			pDriverObject->DriverName.Buffer,
			pDriverObject->DriverName.Length);
	}
}

// !!
// Provides information about all system drivers
/* notes: use locks and non_paged memory */
list_t* GetLoadedDrivers(__out ULONG* pDrivers)
{
	PDRIVER_OBJECT pdrv = g_clientDrvObj;
	PKLDR_DATA_TABLE_ENTRY pldr_drv = (PKLDR_DATA_TABLE_ENTRY)pdrv->DriverSection;
	PKLDR_DATA_TABLE_ENTRY curr = pldr_drv;
	list_t* drivers = NULL;

	if (!pldr_drv){
		return NULL;
	}

	while ((ULONG)curr->LoadOrder.Flink != (ULONG)pldr_drv)
	{
		if (curr->ImageBase && curr->FullModuleName.Length)
		{
			PDRIVER_MODULE pdrv_inf = (PDRIVER_MODULE)PAGE_MEM(sizeof(DRIVER_MODULE));

			if (pdrv_inf)
			{
				memset(pdrv_inf, 0, sizeof(DRIVER_MODULE));

				/* Fills output buffer */
				pdrv_inf->ImageSize = curr->SizeOfImage;
				pdrv_inf->pImageBase = curr->ImageBase;
				pdrv_inf->pEntryPoint = curr->EntryPoint;

				/* .filePath */
				if (curr->FullModuleName.Length < sizeof(pdrv_inf->filePath)){
					memcpy(pdrv_inf->filePath, curr->FullModuleName.Buffer, curr->FullModuleName.Length);
				}

				/* .fileName */
				if (curr->ModuleName.Length < sizeof(pdrv_inf->fileName)){
					memcpy(pdrv_inf->fileName, curr->ModuleName.Buffer, curr->ModuleName.Length);
				}
			}

			if (drivers == NULL){
				drivers = list_create();
			}

			if (list_insert(drivers, pdrv_inf))
			{
				if (pDrivers){
					(*pDrivers)++;
				}
			}
			else
			{
				FreeMemory(pdrv_inf);
			}

			/*
			DbgPrint("cl0: driver=%ws imagebase=%x size=%d",
			curr->FullModuleName.Buffer,
			curr->BaseAddress,
			curr->ImageSize);
			*/
		}

		curr = (PKLDR_DATA_TABLE_ENTRY)curr->LoadOrder.Flink;
	}

	return drivers;
}

PDEVICE_OBJECT GetDeviceInHierarchy(__in WCHAR* dev_name, __out PFILE_OBJECT* pfile)
{
	PDEVICE_OBJECT highestDevice = GetDeviceObject(dev_name, pfile);

	if (!highestDevice){
		return NULL;
	}

	PDEVICE_OBJECT lowestDevice = GetLowestDevice(highestDevice);

	while (lowestDevice)
	{
		if (lowestDevice->Flags & DO_DEVICE_HAS_NAME)
		{
			PUNICODE_STRING pDevName = NULL;
			NTSTATUS got_name = GetObjectName(lowestDevice, &pDevName);

			if (NT_SUCCESS(got_name))
			{
				DbgPrint("cl0: success dev_name\n");
				DbgPrint("cl0: DEVNAME = %ws\n", pDevName->Buffer);

				if (wcscmp(dev_name, pDevName->Buffer) == 0)
				{
					DbgPrint("cl0: device was found \n");
					highestDevice = lowestDevice;
					break;
				}
			}
			else
			{
				DbgPrint("cl0: failed ObQueryNameString\n");
			}

			// Free memory if it was allocated successfully.
			if (pDevName)
			{
				FreeMemory(pDevName);
			}
		}
		else
		{
			DbgPrint("cl0: enumerating devices. drv=%ws, dev_obj=0x%x \n",
				lowestDevice->DriverObject->DriverName.Buffer,
				lowestDevice);
		}

		lowestDevice = lowestDevice->AttachedDevice;
	}

	return highestDevice;
}

// ! Doesn't work now.
list_t* LookupIrpHooks(__in PDEVICE_OBJECT DeviceObject,
	__out ULONG* pCountHookedHandler,
	__in WCHAR* dev_name)
{
	list_t* irp_handlers = NULL;
	PVOID pIrpHandler = NULL;
	PVOID pImageBase = NULL;
	ULONG ImageSize = 0;
	PVOID pRtk_DrvImageBase = NULL;
	EXE_FILE drv_image;

	PDRIVER_OBJECT pDrvObj = DeviceObject->DriverObject;

	// Collecting information about device driver
	if (pDrvObj)
	{
		// 1. Get info from .DriverSection field
		PKLDR_DATA_TABLE_ENTRY pldr_data = (PKLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection;

		if (pldr_data)
		{
			pImageBase = pldr_data->ImageBase;
			ImageSize = pldr_data->SizeOfImage;
		}
		else 
		{
			// 2. Receive image base address of device driver by pointer to DriverEntry
			pImageBase = GetImageBaseByPointer(pDrvObj->DriverInit);

			if (!pImageBase)
			{
				DbgPrint("cl0: error. couldn't receive imagebase of %ws\n", dev_name);
				goto on_exit;
			}

			// Success
			if (InitBase(&drv_image, pImageBase) == 0){
				DbgPrint("cl0: error. couldn't read PE HEADERS of %ws\n", dev_name);
				goto on_exit;
			}

			ImageSize = drv_image.m_pImageNtHeader->OptionalHeader.SizeOfImage;
		}
		
		char dev_drv_file[256];
		DWORD module_name_length = sizeof(dev_drv_file);
		pRtk_DrvImageBase = GetImageBaseByPointer(pImageBase);

		// If destination buffer is too small or it's hidden module.
		if (!GetModuleName(
			pRtk_DrvImageBase,
			dev_drv_file,
			&module_name_length))
		{
			dev_drv_file[0] = 0;
			kstrcpy(dev_drv_file, "hidden module");
		}

		// Prints information about original device driver.
		DbgPrint("cl0: DriverName=%ws Device=%ws DriverEntry=0x%x, ImageBase=0x%x ImageSize=%d bytes FilePath=%s\n",
			pDrvObj->DriverName.Buffer,
			dev_name,
			pDrvObj->DriverInit,
			pImageBase,
			ImageSize,
			dev_drv_file);

		for (long i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			pIrpHandler = pDrvObj->MajorFunction[i];

			// Does that address belong to drivers memory region ?
			if ( ((ULONG)pIrpHandler != g_IrpHandlerStub) &&
				!(((ULONG)pIrpHandler >= (ULONG)pImageBase) &&
				((ULONG)pIrpHandler <= ((ULONG)pImageBase + ImageSize))) )
			{
				PIRP_HANDLER phandler = PAGE_MEM(sizeof(SSDT_HK));
				
				if (phandler)
				{
					pRtk_DrvImageBase = GetImageBaseByPointer(pIrpHandler);

					phandler->handler = pIrpHandler;
					phandler->imagebase = pRtk_DrvImageBase;
					phandler->major_code = i;

					DWORD module_name_length = sizeof(phandler->module);
					BOOLEAN got_name = GetModuleName(
						phandler->imagebase,
						phandler->module,
						&module_name_length);

					// If destination buffer is too small or it's hidden module
					if (!got_name)
					{
						phandler->module[0] = 0;
						kstrcpy(phandler->module, "hidden module");
					}

					if (irp_handlers == NULL)
						irp_handlers = list_create();

					if (list_insert(irp_handlers, phandler)) {
						if (pCountHookedHandler) {
							(*pCountHookedHandler)++;
						}
					}

					// Hooked IRP handler
					DbgPrint("cl0:hooked irp_handler[0x%x]=0x%x ( 0x%x : %s )\n",
						phandler->major_code,
						phandler->handler,
						phandler->imagebase,
						phandler->module);
				}
			} else
			{ // valid address
				DbgPrint("cl0:ok. irp_handler[0x%x]=0x%x\n",
					i,
					pIrpHandler);
			}
			// print information
		}
	}
	else 
	{
		DbgPrint("cl0: couldn't connect to %ws device\n", dev_name);
	}

	// ON EXIT
on_exit:

	return irp_handlers;
}

list_t* LookupIrpHooksInDevStack(__in WCHAR* dev_name, __out ULONG* pCountHookedHandler)
{
	list_t* irp_handlers = NULL;
	PFILE_OBJECT pfile = NULL;

	// 1. Get pointer to the highest device in stack.
	PDEVICE_OBJECT DeviceObject = GetDeviceObject(dev_name, &pfile);

	if (DeviceObject)
	{
		// 2. Get pointer to the lowest device.
		// for( move_to device with flag DO_DEVICE_HAS_NAME)
		DeviceObject = GetLowestDevice(DeviceObject);
		while (DeviceObject)
		{
			ULONG length = 0;
			list_t* hooks = LookupIrpHooks(DeviceObject, &length, dev_name);

			// If the list is not empty
			if (length)
			{
				// Connects two new list to common list
				if (irp_handlers)
				{
					list_t* tail = list_tail(irp_handlers);
					tail->pNext = hooks;
				}
				else {
					irp_handlers = hooks;
				}
			}

			if (pCountHookedHandler){
				*pCountHookedHandler += length;
			}

			DeviceObject = DeviceObject->AttachedDevice;
		}
	}

	if (pfile != NULL)
		ObDereferenceObject(pfile);

	return irp_handlers;
}

/* Retrievals information about all devices which are placed above */
list_t* GetAttachedDevices(__in WCHAR* pDeviceName, __out ULONG* pNumberOfDevices)
{
	PFILE_OBJECT pfile = NULL;
	list_t* devices_lst = NULL;
	PDEVICE_OBJECT deviceObject = GetDeviceInHierarchy(pDeviceName, &pfile);

	if (!deviceObject){
		return NULL;
	}

	if (pNumberOfDevices){
		*pNumberOfDevices = 0;
	}

	// Get attached device to the lowest device in device hierarchy.
	PDEVICE_OBJECT pAttachedDevice = deviceObject->AttachedDevice;

	ulong level = 0;
	while (pAttachedDevice)
	{
		DbgPrint("cl0: level=%d pDeviceObject=0x%x Characteristics=0x%x DeviceType=0x%x Flags=0x%x\n",
			level,
			pAttachedDevice,
			pAttachedDevice->Characteristics,
			pAttachedDevice->DeviceType,
			pAttachedDevice->Flags);

		PDEVICE_INFO pDeviceInfo = PAGE_MEM(sizeof(DEVICE_INFO));

		// Reads and saves information from DRIVER_OBJECT.
		if (pDeviceInfo)
		{
			// Collect device info.
			PUNICODE_STRING pDeviceName = NULL;
			GetObjectName(pAttachedDevice, &pDeviceName);
			if (pDeviceName)
			{
				if (pDeviceName->Length < sizeof(pDeviceInfo->device_name))
				{
					memcpy(pDeviceInfo->device_name, pDeviceName->Buffer, pDeviceName->Length);
				}

				FreeMemory(pDeviceName);
			}
			else
			{
				// Unnamed device or hidden device name.
				pDeviceInfo->device_name[0] = 0;
			}

			// Collect driver info.
			GetDriverObjectInfo(pAttachedDevice->DriverObject, &pDeviceInfo->driver_info);

			// Print information.
			DbgPrint("cl0: DriverName=%ws FilePath=%ws ImageBase=0x%x ImageSize=0x%x DeviceObject=0x%x\n",
				pDeviceInfo->driver_info.driver_name,
				pDeviceInfo->driver_info.driver_module.filePath,
				pDeviceInfo->driver_info.driver_module.pImageBase,
				pDeviceInfo->driver_info.driver_module.ImageSize,
				pAttachedDevice);
		}

		if (devices_lst == NULL){
			devices_lst = list_create();
		}

		if (list_insert(devices_lst, pDeviceInfo))
		{
			if (pNumberOfDevices){
				(*pNumberOfDevices)++;
			}
		}
		else
		{
			// If couldn't insert an element to the list than free memory.
			FreeMemory(pDeviceInfo);
		}

		level++;
		pAttachedDevice = pAttachedDevice->AttachedDevice;
	}

	if (pfile){
		ObDereferenceObject(pfile);
	}

	return devices_lst;
}

BOOLEAN SetOffsets()
{
	switch (*NtBuildNumber)
	{
	case  2195:  // Win 2k
		off_EPROCESS_ActiveProcessLink = 0xA0;
		off_EPROCESS_ProcessName = 0x01FC;
		off_EPROCESS_PID = 0x09C;
		off_EPROCESS_RootVad = 0;
		break;
	case 2600:   // Win XP
		off_EPROCESS_ActiveProcessLink = 0x88;
		off_EPROCESS_ProcessName = 0x174;
		off_EPROCESS_PID = 0x084;
		off_EPROCESS_RootVad = 0x11C;
		off_EPROCESS_RootVad = 0;
		break;
	case 3790:  // W2K3
		off_EPROCESS_ActiveProcessLink = 0x98;
		off_EPROCESS_ProcessName = 0x164;
		off_EPROCESS_PID = 0x094;
		off_EPROCESS_RootVad = 0;
		break;

	case 7601: // Win 7
		off_EPROCESS_ActiveProcessLink = 0xB8;
		off_EPROCESS_ProcessName = 0x16c;
		off_EPROCESS_PID = 0xb4;
		off_EPROCESS_RootVad = 0x278;
		break;

		// CASE Vista;
		// case Win 8

	default:
		return FALSE;
	}

	return TRUE;
}

BOOLEAN AttachToKernel()
{
	int initialized = InitBase(&g_ExeNtoskernl, g_ntoskrnl_addr);
	InitExport(&g_ExeNtoskernl);
	InitSection(&g_ExeNtoskernl);
	
	if (!SetOffsets()){
		DbgPrint("cl0: system offsets weren't calculated.\n");
	}

	return initialized != 0;
}

NTSTATUS ConnectToSysApi()
{
	PVOID ptr_KeServiceDescriptorTable = GetExportedFn(&g_ExeNtoskernl, "KeServiceDescriptorTable");

	PVOID pServicesTable = (((PUCHAR)g_ntoskrnl_addr) + g_SDT_offset_ntoskrnl);
	
	// 1. ZwQuerySystemInformation address in mapped kernel file
	PVOID pfn_QuerySysInfo1 = (PVOID)GetExportedFn(&g_kernel_mapped_file, "ZwQuerySystemInformation");

	// 2. Gets index number of ZwQuerySystemInformation
	ULONG* pfn_index = (ULONG*)((PCHAR)pfn_QuerySysInfo1 + 1);

	// 3. Gets pointer to original ZwQuerySystemInformation from SDT
	PDWORD original_pfn = (PDWORD)(((PUCHAR)g_kernel_mapped_addr) + g_SDT_offset_ntoskrnl + (*pfn_index) * sizeof(DWORD));

	// 4. Calculates address of original ZwQuerySystemInformation
	ULONG offset_to_original_fn = *original_pfn - g_kernel_mapped_file.m_pImageNtHeader->OptionalHeader.ImageBase;
	ULONG addr_original_fn = (ULONG)g_ntoskrnl_addr + offset_to_original_fn;

	// 5. Save pointer to ZwQuerySystemInformation
	sysapi_ZwQuerySystemInformation = (PZwQuerySystemInformation)addr_original_fn;

	// ! I use it only for test
	sysapi_ZwQuerySystemInformation = (PZwQuerySystemInformation)GetExportedFn(&g_ExeNtoskernl, "ZwQuerySystemInformation");

	////////////////////////////////////////////////////////////////////

	DbgPrint("KeServiceDescriptorTable by import: %x export:%x\n",
		KeServiceDescriptorTable,
		ptr_KeServiceDescriptorTable);

	if (ptr_KeServiceDescriptorTable)
	{
		// Import table of this driver was modified
		if (ptr_KeServiceDescriptorTable != (PVOID)KeServiceDescriptorTable)
		{
			DbgPrint("cl0: warning! SSDT by import isn't equal to the export value\n");
			KeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)ptr_KeServiceDescriptorTable;
		}
	}
	else
	{
		DbgPrint("cl0: KeServiceDescriptorTable wasn't found in export section\n");
	}

	DbgPrint("cl0: conn. sysapi index=%x (0x%x)"\
		"offset=%x address=0x%x\n",
		(*pfn_index),
		pfn_QuerySysInfo1,
		offset_to_original_fn,
		addr_original_fn);

	return STATUS_SUCCESS;
}

PVOID GetBasePtr(__in PVOID ptr, __out CHAR* pName, __inout ULONG* pLenght)
{
	//MiCheckVirtualAddress()
	return NULL;
}

BOOLEAN CheckCode(__in PVOID begin,
	__in ULONG srch_area,
	__in PVOID border,
	__in PVOID pOriginalCode,
	__out PCODE_INJECTION pInjection)
{
	//
	return FALSE;
}

/* This procedure searches any changes in binary code of kernel module. */
list_t* LookupCodeInjections(__in PEXE_FILE pLoadedImage,
	__in PEXE_FILE pMappedImage,
	__out ULONG* changedBlocks)
{
	list_t* changed_blocks = NULL;
	ulong srch_distance = 50;
	PVOID border = NULL;
	char _text[] = ".text";

	/* Calculate min and MAX limit. */
	
	QSortFns(pLoadedImage->m_export, 0, GET_MAX_POINT(pLoadedImage->m_export_length));
	QSortFns(pMappedImage->m_export, 0, GET_MAX_POINT(pMappedImage->m_export_length));

	/* Search changes in exported functions. */
	ulong export_length = pLoadedImage->m_export_length;
	for (ulong i = 0; i < export_length; ++i)
	{
		PEXPORT_FN pExpObj = pLoadedImage->m_export + i;
		ulong distance = srch_distance;

		if (pExpObj->Name)
		{
			DbgPrint("cl0: exp.obj %s=%x", pExpObj->Name, pExpObj->addr);
		}

		/* Skip if it's a forwarding mechanism. */
		if (pExpObj->forwarding){
			continue;
		}

		PIMAGE_SECTION_HEADER section = GetSectionByAddr(pLoadedImage, pExpObj->addr);
		if (!section){
			continue;
		}

		char sec_name[sizeof(section->Name) + 1];
		RtlZeroMemory(sec_name, sizeof(sec_name));
		memcpy(sec_name, section->Name, sizeof(section->Name));

		DbgPrint("cl0: section[%s], va=0x%x\n", sec_name, section->VirtualAddress);

		/* Skip writable exported data - global variables, pointers etc. */
		if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
		{
			char buf[sizeof(section->Name) + 1];
			RtlZeroMemory(buf, sizeof(buf));
			memcpy(buf, section->Name, sizeof(section->Name));
			DbgPrint("cl0: INIMAGE_SCN_MEM_EXECUTE, name=%s, charact.=0x%x\n",
				buf,
				section->Characteristics);

			continue;
		}

		/* Border it's end of section where exported object was placed. */
		border = (PVOID)(section->VirtualAddress + section->Misc.VirtualSize);

		/* If its not last function try to decrease search area. */
		if (i + 1 < export_length)
		{
			/* Get address of next exported function which address is higher. */
			PEXPORT_FN nextObj = pLoadedImage->m_export + i + 1;
			ULONG new_distance = (UCHAR*)nextObj->addr - (UCHAR*)pExpObj->addr;

			/* Decrease search distance. */
			if (new_distance < distance)
			{
				distance = new_distance;
				border = (UCHAR*)pExpObj->addr + distance;
			}

			if (nextObj->Name){
				DbgPrint("cl0: next exp.obj %s = 0x%x \n", nextObj->Name, nextObj->addr);
			}
		}

		/* Change distance if next exported object placed in different section. */
		if (distance > (ulong)border - (ulong)pExpObj->addr)
		{
			distance = (ulong)border - (ulong)pExpObj->addr;
		}

		/* Find pointer to original exported object's data. */
		/* Expression:
			addr_in_export_table = (current_addr - image_base) + mapped_file_addr */
		PVOID target = (PVOID)(((ulong)pExpObj->addr - (ulong)pLoadedImage->m_base_x) + (ulong)pMappedImage->m_base_x);

		DbgPrint("cl0: LookupFn %s=0x%x, by addr=0x%x, dist.=%d \n",
			pExpObj->Name,
			pExpObj->addr,
			target,
			distance
			);

		int i_exp = LookupFn(pMappedImage->m_export, 0, GET_MAX_POINT(pMappedImage->m_export_length), target);
		if (i_exp == -1)
		{
			DbgPrint("cl0: not found.\n");
			continue;
		} 

		CODE_INJECTION ci;
		RtlZeroMemory(&ci, sizeof(ci));
		PEXPORT_FN pOriginalObj = pMappedImage->m_export + i_exp;
		BOOLEAN changed = CheckCode(pExpObj->addr, distance, border, pOriginalObj->addr, &ci);

		DbgPrint("cl0: Verify_code(..). border=0x%x, distance=%d, addr=0x%x, mapped_addr=0x%x\n",
			border,
			distance,
			pExpObj->addr,
			pOriginalObj->addr);
		
		if (changed)
		{
			PCODE_INJECTION pci = NONPAGED_MEM(sizeof(CODE_INJECTION));

			if (pci)
			{
				memcpy(pci, &ci, sizeof(CODE_INJECTION));

				if (changed_blocks == NULL){
					changed_blocks = list_create();
				}

				if (list_insert(changed_blocks, pci))
				{
					if (changedBlocks){
						(*changedBlocks)++;
					}
				}
				else
				{
					/*! should destroy empty nodes in a list. */
					FreeMemory(pci);
				}
			}
		}
	}

	/* Search code changes in SDT[i]. */
	/* ... */

	return changed_blocks;
}

NTSTATUS DriverDispatchControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PCL0_REQUEST presponse = NULL, prequest = NULL;
	PCHAR pBody = NULL;
	WCHAR* pdevice_name = NULL;
	ULONG requestCode, written = 0, requiredSize = 0;
	PIO_STACK_LOCATION stack;
	NTSTATUS IO_status = STATUS_SUCCESS, call_state = CL0_BUFFER_TOO_SMALL;

	stack = IoGetCurrentIrpStackLocation(Irp);
	requestCode = stack->Parameters.DeviceIoControl.IoControlCode;

	DWORD inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	DWORD outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;

	// for NEITHER method
	PVOID pInput = stack->Parameters.DeviceIoControl.Type3InputBuffer;
	PVOID pOutput = Irp->UserBuffer;

	// for BUFFERD method
// 	PVOID pInput = Irp->AssociatedIrp.SystemBuffer;
// 	PVOID pOutput = Irp->AssociatedIrp.SystemBuffer;

	prequest = (PCL0_REQUEST)pInput;
	presponse = (PCL0_REQUEST)pOutput;
	
	DbgPrint("cl0: new irp, input size %d output size %d\n", inputSize, outputSize);

	// PASSIVE_LEVEL
	switch (stack->MajorFunction)
	{
	case IRP_MJ_CREATE:
	case IRP_MJ_SHUTDOWN:
	case IRP_MJ_CLOSE:
		break;

	case IRP_MJ_DEVICE_CONTROL:

		//	Successful response contains two fields:
		// 1. CL0_REQUEST as a response (result of the request)
		// 2. Body of the response (which are described in the first filed CL0_REQUEST)
		// Failed response it's a CL0_REQUEST

		BUILD_RESPONSE(pOutput, pInput);
		pBody = GET_BODY(presponse);
		written = sizeof(CL0_REQUEST);

		if (prequest)
		{
			DbgPrint("cl0: request packet. bodysize=%d (.data=0x%x) .arg=0x%x\n", 
				prequest->bodysize,
				prequest->data,
				prequest->arg);
		}

		switch(requestCode)
		{

		// Save CL0_REQUEST in output buffer and work with it there
		//memcpy(pOutput, pInput, sizeof(CL0_REQUEST));
		//pResponse = (PVOID)pOutput;

		case IOCTL_CL0_VERSION:
			// On this type of request the driver informs its version in .result field
			
			DbgPrint("cl0: CL0_VERSION is %d\n", CL0_VERSION);
			presponse->error = CL0_SUCCESS;
			presponse->result = CL0_VERSION;
			break;

		// Retrievals address of kernel module from user application
		case IOCTL_KERNELBASE:
			//////////////////////////////////////////////////////////////////////////
			// Receives packet in following format:
			// -arg - kernel image base
			// -body - kernel file path (ansi)
			// Format of returned data:
			// -error

			if (gDriverIsConfigured)
			{
				DbgPrint("cl0: driver was configured earlier\n");
				break;
			}

			InterlockedExchangePointer(&g_ntoskrnl_addr, (PVOID)(*(PDWORD)&((PCL0_REQUEST)pInput)->arg));
			DbgPrint("cl0: kernel is loaded to %x\n", g_ntoskrnl_addr);

			DbgPrint("cl0: SYSENTER_HANDLER 0x%x ( offset 0x%x )\n",
				SysenterHandler(),
				SysenterHandler() - (ULONG)g_ntoskrnl_addr);

			// Connects to system's API
			int attached = AttachToKernel();
			presponse->result = 0;
			presponse->error = CL0_KRNL_NOT_CONNECTED;

			if (attached)
			{
				// 1. Gets original pointer to KeServiceDescriptorTable
				g_ptrSDT = (PSERVICE_DESCRIPTOR_TABLE)GetExportedFn(&g_ExeNtoskernl,
					"KeServiceDescriptorTable");

				DbgPrint("cl0: offset to KeServiceDescriptorTable 0x%x\n",
					(DWORD)g_ptrSDT - (DWORD)g_ExeNtoskernl.m_base_x);

				// 2. Is pointer to KiSystemServicesTable hooked ?
				if (!(((ULONG)g_ptrSDT->ntoskrnl.ServiceTable >= (ULONG)g_ntoskrnl_addr) &&
					((ULONG)g_ptrSDT->ntoskrnl.ServiceTable <= ((ULONG)g_ntoskrnl_addr +
					g_ExeNtoskernl.m_pImageNtHeader->OptionalHeader.SizeOfImage))))
				{
					DbgPrint("cl0:error. KiSystemServicesTable = 0x%x was changed\n",
						g_ptrSDT->ntoskrnl.ServiceTable);
					break;
				}

				// 3. Calculates offset to the SSDT in memory
				g_SDT_offset_ntoskrnl = (ULONG)g_ptrSDT->ntoskrnl.ServiceTable - (ULONG)g_ExeNtoskernl.m_base_x;

				DbgPrint("cl0: ssdt.ntoskrnl addr 0x%x (offset 0x%x)",
					g_ptrSDT->ntoskrnl.ServiceTable,
					g_SDT_offset_ntoskrnl);

				//MultiByteToWideChar()
				RtlInitAnsiString(&gKrnlFilePath, REQUEST_BODY(prequest));
				RtlAnsiStringToUnicodeString(&gwKrnlFilePath, &gKrnlFilePath, TRUE);

				DbgPrint("cl0: size of kernel image OS: %d\n",
					g_ExeNtoskernl.m_pImageNtHeader->OptionalHeader.SizeOfImage);

				// At this point the driver loads and creates mapping private copy of kernel file
				g_kernel_mapped_addr = (PVOID)LoadFile(gwKrnlFilePath.Buffer,
					g_ExeNtoskernl.m_pImageNtHeader->OptionalHeader.SizeOfImage,
					&g_hKernelFile,
					&g_hKernelSection);

				if (!g_kernel_mapped_addr)
				{
					DbgPrint("cl0: unknown error. %s wasn't loaded\n", gKrnlFilePath.Buffer);
					break;
				}

				DbgPrint("cl0: %s was loaded to %x\n",
					gKrnlFilePath.Buffer,
					g_kernel_mapped_addr);

				// Receives information about export functions from original binary file
				if (!InitBase(&g_kernel_mapped_file, g_kernel_mapped_addr))
				{
					DbgPrint("cl0: unknown error. %s wasn't recognized\n", gKrnlFilePath.Buffer);
					break;
				}
				
				// Gets information about all exported functions from HD
				InitExport(&g_kernel_mapped_file);
				InitSection(&g_kernel_mapped_file);
				NTSTATUS connected = ConnectToSysApi();

				DbgPrint("cl0: connecting to the system API interface = %x\n", connected);
				
				gDriverIsConfigured = TRUE;
				presponse->error = CL0_SUCCESS;
			}
			
			break;

		case IOCTL_SSDT_SCAN:
			DRIVER_IS_CONFIGURED;
			//////////////////////////////////////////////////////////////////////////
			// Receives packet in following format:
			// -bodysize - describes output buffer
			// Format of returned data:
			// -result -  contains size of returned data (in bytes) or required size if
			// input buffer is too small to receive data
			// -error

			ULONG hookedServices = 0;
			list_t* list_hooks = LookupSsdtHooks(&hookedServices);
			presponse->result = hookedServices * sizeof(SSDT_HK);

			// error: output buffer is too small to receive data..
			if (hookedServices * sizeof(SSDT_HK) > presponse->bodysize)
			{
				/* Set error flag. */
				presponse->error = CL0_BUFFER_TOO_SMALL;
				DbgPrint("client0: error IOCTL_SCAN_SSDT  required %d\n", presponse->result);
			}
			else 
			{
				presponse->error = CL0_SUCCESS;
				list_to_buffer(list_hooks, GET_BODY(presponse), sizeof(SSDT_HK));
				written += hookedServices * sizeof(SSDT_HK);

				DbgPrint("client0: IOCTL_SCAN_SSDT wrote to output %d\n",
					presponse->result);
			}

			list_erase(list_hooks);
			break;

		case IOCTL_SSDT_RESET:
			DRIVER_IS_CONFIGURED;
			// .arg field contains number of system service which should be recovered
			// other fields are not important

			DbgPrint("cl0: IOCTL_REMOVE_SSDT_HK remove srv %d (0x%x) \n",
				presponse->arg,
				presponse->arg);

			RemoveHookInSdt(presponse->arg);
			presponse->error = CL0_SUCCESS;

			break;

		case IOCTL_SYSENTER_CHECK:
			DRIVER_IS_CONFIGURED;

			if (presponse->bodysize >= sizeof(SYSENTER_HANDLER))
			{
				presponse->error = CL0_SUCCESS;
				presponse->bodysize = sizeof(SYSENTER_HANDLER);
				LookupSysenterHook((PSYSENTER_HANDLER)pBody);
				written += sizeof(SYSENTER_HANDLER);
			}
			else
			{
				/* error. output buffer is too small */
				presponse->error = CL0_BUFFER_TOO_SMALL;
				presponse->result = sizeof(SYSENTER_HANDLER);
			}

			break;

		case IOCTL_IRP_HANDLERS:
			DRIVER_IS_CONFIGURED;
			//////////////////////////////////////////////////////////////////////////
			// Receives packet in following format:
			// -bodysize - describes output buffer in bytes
			// -arg - length of DEVICE_NAME in bytes
			// Format of returned data:
			// -result -  contains size of returned data (in bytes) or required size if
			// if output buffer (body part) is too small to receive data
			// -error = CL0_BUFFER_TOO_SMALL

			//!!! FOR TEST
			DbgPrint("ImageMapped.NtHeader.ImageBase = 0x%x, base_x=0x%x\n",
				g_kernel_mapped_file.m_pImageNtHeader->OptionalHeader.ImageBase,
				g_kernel_mapped_file.m_base_x);

			DbgPrint("ImageKernel.NtHeader.ImageBase = 0x%x, base_x=0x%x\n",
				g_ExeNtoskernl.m_pImageNtHeader->OptionalHeader.ImageBase,
				g_ExeNtoskernl.m_base_x);

			LookupCodeInjections(&g_ExeNtoskernl, &g_kernel_mapped_file, 0);

			pdevice_name = (WCHAR*)GET_BODY(prequest);

			DbgPrint("cl0: IOCTL_IRP_HANDLERS find IRP hooks in %ws dev hierarchy\n",
				pdevice_name);

			ULONG hooked_irp = 0;
			list_t* irp_hooks = LookupIrpHooksInDevStack(pdevice_name, &hooked_irp);
			requiredSize = hooked_irp  * sizeof(IRP_HANDLER);
			presponse->result = requiredSize;

			// error: output buffer is too small to receive data..
			if (requiredSize > presponse->bodysize)
			{
				presponse->error = CL0_BUFFER_TOO_SMALL;
				DbgPrint("cl0: error. output buffer is too small, required %d bytes\n", requiredSize);
			}
			else
			{
				presponse->error = CL0_SUCCESS;
				list_to_buffer(irp_hooks, GET_BODY(presponse), sizeof(IRP_HANDLER));
				written += requiredSize;
			}

			list_erase(irp_hooks);
			break;

		case IOCTL_DRIVERS:
			DRIVER_IS_CONFIGURED;
			//////////////////////////////////////////////////////////////////////////
			// Receives packet in following format:
			// -bodysize - describes output buffer in bytes
			// Format of returned data:
			// -result -  contains size of returned data (in bytes) or required size
			// if output buffer (body part) is too small to receive data
			// -error = CL0_BUFFER_TOO_SMALL

			//SystemDevices();

			DbgPrint("cl0: IOCTL_DRIVERS \n");
			
			ULONG loadedDrivers = 0;
			list_t* pDrvList = GetLoadedDrivers(&loadedDrivers);
			requiredSize = loadedDrivers * sizeof(DRIVER_MODULE);
			presponse->result = requiredSize;

			// error: output buffer is too small to receive data..
			if (requiredSize > presponse->bodysize)
			{
				presponse->error = CL0_BUFFER_TOO_SMALL;
				DbgPrint("cl0: error. output buffer is too small, required %d bytes\n", requiredSize);
			}
			else
			{
				presponse->error = CL0_SUCCESS;
				list_to_buffer(pDrvList, GET_BODY(presponse), sizeof(DRIVER_MODULE));
				written += requiredSize;
			}

			list_erase(pDrvList);
			break;

		case IOCTL_ATTACHED_DEVICES:
			DRIVER_IS_CONFIGURED;
			//////////////////////////////////////////////////////////////////////////
			// Receives packet in following format:
			// -bodysize - describes output buffer in bytes
			// -arg - length of DEVICE_NAME in bytes
			// Format of returned data:
			// -result -  contains size of returned data (in bytes) or required size if
			// if output buffer (body part) is too small to receive data
			// -error = CL0_BUFFER_TOO_SMALL

			//! FOR TEST!
			List_Vad();
			//////////////////////////////////////////////////////////////////////////

			pdevice_name = (WCHAR*)GET_BODY(prequest);
			DbgPrint("cl0: IOCTL_ATTACHED_DEVICES to %ws\n", pdevice_name);

			ULONG numberOfDevices = 0;
			list_t* devList = GetAttachedDevices(pdevice_name, &numberOfDevices);
			requiredSize = numberOfDevices  * sizeof(DEVICE_INFO);
			presponse->result = requiredSize;

			// error: output buffer is too small to receive data..
			if (requiredSize > presponse->bodysize)
			{
				presponse->error = CL0_BUFFER_TOO_SMALL;
				DbgPrint("cl0: error. output buffer is too small, required %d bytes\n", requiredSize);
			}
			else
			{
				presponse->error = CL0_SUCCESS;
				list_to_buffer(devList, GET_BODY(presponse), sizeof(DEVICE_INFO));
				written += requiredSize;
			}

			list_erase(devList);
			break;

		case IOCTL_SYSENTER_RESET:
			DRIVER_IS_CONFIGURED;
			// Removes SYSENTER hook

			presponse->error = ResetSysenter() != TRUE ? CL0_UNKNOWN_ERROR : CL0_SUCCESS;
			presponse->bodysize = 0;

			break;

		case IOCTL_GET_KRNL_MODULES:
			DRIVER_IS_CONFIGURED;

			DbgPrint("cl0: IOCTL_GET_KRNL_MODULES \n");

			requiredSize = presponse->bodysize;
			call_state = GetLoadedSysModules(&requiredSize, pBody);

			// Saves required size for the output buffer
			presponse->result = requiredSize;

			if (call_state == STATUS_SUCCESS)
			{
				written += requiredSize;
				presponse->error = CL0_SUCCESS;
			}
			else
			{
				DbgPrint("cl0: error. CL0_BUFFER_TOO_SMALL required %d bytes.\n", requiredSize);
				presponse->error = CL0_BUFFER_TOO_SMALL;
			}

			break;

		case IOCTL_GET_PROCESSES:
			DRIVER_IS_CONFIGURED;

			DbgPrint("cl0: IOCTL_GET_PROCESSES\n");
			requiredSize = presponse->bodysize;
			call_state = GetLoadedProcesses(&requiredSize, pBody);

			// Save required size for the output buffer
			presponse->result = requiredSize;

			if (call_state == STATUS_SUCCESS)
			{
				presponse->error = CL0_SUCCESS;
				written += requiredSize;
			}
			else
			{
				DbgPrint("cl0: error. CL0_BUFFER_TOO_SMALL required %d bytes.\n", requiredSize);
				presponse->error = CL0_BUFFER_TOO_SMALL;
			}

			break;

		case IOCTL_GET_PROC_MODULES:
			DRIVER_IS_CONFIGURED;

			break;

		DRIVER_UNPREPARED:
			DbgPrint("cl0:(error) driver is not prepared to work.\n");
			presponse->error = CL0_UNPREPARED;
			presponse->result = 0;
			break;

		default:
			break;
		}

	default:
		break;
	}

	DbgPrint("cl0: written to output %d bytes\n", written);

	// Completes request here
	Irp->IoStatus.Information = written;
	Irp->IoStatus.Status = IO_status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return IO_status;
}

void DriverUnload(IN PDRIVER_OBJECT pDrvObj)
{
	DbgPrint("cl0: DriverUnload\n");

	if (gDriverIsConfigured)
	{
		ZwClose(g_hKernelSection);
		ZwClose(g_hKernelFile);
		//RtlFreeUnicodeString(gwKrnlFilePath);

		ExeFileFree(&g_ExeNtoskernl);
		ExeFileFree(&g_kernel_mapped_file);
	}

	IoDeleteSymbolicLink(&deviceLinkUnicodeString);
	IoDeleteDevice(pDrvObj->DeviceObject);
}

NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING pusRegistryPath)
{
	NTSTATUS	init_status;
	DbgPrint("cl0: NtBuildNumber=%d, regkey %ws drv_size %d\n",
		*NtBuildNumber,
		pusRegistryPath->Buffer,
		DriverObject->Size);

	RtlInitUnicodeString (&deviceNameUnicodeString, DEVICE_NAME );
	RtlInitUnicodeString (&deviceLinkUnicodeString, DEVICE_LINK );

	init_status = IoCreateDevice ( DriverObject,
		0,
		&deviceNameUnicodeString,
		CLIENT0_DEVICE,
		0,
		TRUE,
		&g_clientDevObj);

	if(! NT_SUCCESS(init_status))
	{
		DbgPrint(("client_0: Failed to create device!\n"));
		return init_status;
	}

	init_status = IoCreateSymbolicLink (&deviceLinkUnicodeString, &deviceNameUnicodeString );
	
	if(! NT_SUCCESS(init_status))
	{
		DbgPrint("cl0: Failed to create symbolic link!\n");
		IoDeleteDevice(DriverObject->DeviceObject);
		return init_status;
	}

	g_clientDrvObj = DriverObject;

	// Saves address of default IRP handler
	g_IrpHandlerStub = DriverObject->MajorFunction[IRP_MJ_CREATE];
	DbgPrint("cl0: default irp_handler_stub %x \n", g_IrpHandlerStub); 

	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]       =
	DriverObject->MajorFunction[IRP_MJ_CREATE]         =
	DriverObject->MajorFunction[IRP_MJ_CLOSE]          =
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatchControl;
	DriverObject->DriverUnload = DriverUnload;

	return init_status;
}
