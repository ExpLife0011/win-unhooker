
//      (c)VsoftLab 2006 - 2014
//		Author: burluckij@gmail.com	


#include "System.h"

using namespace Memory;

// x86
const UCHAR stub_PEB[] = {
	0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, // mov eax, fs:[0x30]
	0xC3 //  retn
};

#define KERNEL_DLL "kernel32.dll"

#define get_header_addr(hModule)				(void*)(hModule + (((PIMAGE_DOS_HEADER)hModule)->e_lfanew))

struct{
	char* szPrivName;
}

privilages[] = {
	"SeCreateTokenPrivilege","SeAssignPrimaryTokenPrivilege","SeLockMemoryPrivilege","SeIncreaseQuotaPrivilege",
	"SeUnsolicitedInputPrivilege","SeMachineAccountPrivilege","SeTcbPrivilege",
	"SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege","SeSystemProfilePrivilege",
	"SeSystemtimePrivilege","SeProfileSingleProcessPrivilege","SeIncreaseBasePriorityPrivilege",
	"SeCreatePagefilePrivilege","SeCreatePermanentPrivilege","SeBackupPrivilege",
	"SeRestorePrivilege","SeShutdownPrivilege","SeDebugPrivilege","SeAuditPrivilege",
	"SeSystemEnvironmentPrivilege","SeChangeNotifyPrivilege","SeRemoteShutdownPrivilege","SeUndockPrivilege",
	"SeSyncAgentPrivilege","SeEnableDelegationPrivilege","SeManageVolumePrivilege"
};

PVOID Memory::getmem(__in size_t x)
{
	return (PVOID)((char*)new (std::nothrow) char[x]);
}

void Memory::freemem(__in PVOID x)
{ 
	char* p = (char*)x;
	delete[] p;
}

BOOL System::LoadDriver(__in const char* szService)
{
	BOOL started = FALSE;
	SC_HANDLE hOpenSM;
	SC_HANDLE hDrvService;

	hOpenSM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hOpenSM)
		return FALSE;

	hDrvService = OpenService(hOpenSM, szService, SERVICE_ALL_ACCESS);
	if (hDrvService)
	{
		started = StartServiceA(hDrvService, 0, (LPCSTR*)szService);
// 		if((started==FALSE) && (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)){
// 			started = TRUE;
// 		}

		CloseServiceHandle(hDrvService);
	}

	CloseServiceHandle(hOpenSM);
	return started;
}

BOOL System::UnloadDriver(__in const char* szService)
{
	BOOL unloaded = FALSE;
	SC_HANDLE hOpenSM;
	SC_HANDLE hDrvService;
	SERVICE_STATUS srv_state;

	hOpenSM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hOpenSM) {
		return FALSE;
	}

	hDrvService = OpenService(hOpenSM, szService, SERVICE_ALL_ACCESS);
	if (hDrvService)
	{
		unloaded = ControlService(hDrvService, SERVICE_CONTROL_STOP, &srv_state);
		CloseServiceHandle(hDrvService);
	}

	CloseServiceHandle(hOpenSM);
	return unloaded;
}

BOOL System::CreateDriverService(__in DWORD dwStartType, __in const char* szService, __in const char* szDriverFile)
{
	SC_HANDLE hOpenSM;
	SC_HANDLE hDrvService;

	hOpenSM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hOpenSM)
		return FALSE;

	hDrvService = CreateServiceA( 
		hOpenSM,	// SCM database 
		szService,	// name of service 
		szService,	// service name to display 
		SERVICE_ALL_ACCESS,        // desired access 
		SERVICE_KERNEL_DRIVER,		// service type 
		dwStartType,				// start type 
		SERVICE_ERROR_NORMAL,      // error control type 
		szDriverFile,			// path to service's binary 
		NULL,                      // no load ordering group 
		NULL,                      // no tag identifier 
		NULL,                      // no dependencies 
		NULL,                      // LocalSystem account 
		NULL
		);

	if(hDrvService)
		CloseServiceHandle(hDrvService);

	CloseServiceHandle(hOpenSM);
	return(hDrvService != NULL);
}

BOOL System::NtInitSystemInformation()
{
	pfnNtQuerySystemInformation = (FPFN_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
	pfnNtQueryInformationProcess = (FPFN_NtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

	return (pfnNtQuerySystemInformation && pfnNtQueryInformationProcess);
}

DWORD System::GetPeb(DWORD dwPid)
{
	LPVOID	pToPebBuffer;
	DWORD	dwSize = sizeof (stub_PEB);
	HANDLE	hProcess;
	HANDLE	hThread;
	DWORD	dwResult=0; // will contain pointer to the PEB

	if(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid))
	{
		if(pToPebBuffer = VirtualAllocEx(hProcess, NULL, dwSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		{
			if(WriteProcessMemory(hProcess, pToPebBuffer, stub_PEB, dwSize, NULL))
			{
				if(hThread = CreateRemoteThread(hProcess, NULL, 0x30, (LPTHREAD_START_ROUTINE)pToPebBuffer, NULL, 0, NULL)){
					do
					{
						if(!GetExitCodeThread(hThread, &dwResult))
							dwResult = 0; // exit if occurred error

					} while(dwResult==STILL_ACTIVE);
					CloseHandle(hThread);
				}
			}

			VirtualFreeEx(hProcess, pToPebBuffer, 0/*dwSize*/, MEM_RELEASE);
		}

		CloseHandle(hProcess);
	}

	return dwResult;
}

bool System::WriteToFile(__in const char* szFile, __in const PVOID pData, __in DWORD dwSize, __in DWORD flagCreated)
{
	HANDLE file = INVALID_HANDLE_VALUE;
	DWORD dwWritten;
	BOOL result = false;

	if(szFile)
	{
		file = CreateFileA(szFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, flagCreated, 0, 0);
		if (file != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(file, 0, 0, FILE_END);
			result = WriteFile(file, pData, dwSize, &dwWritten, NULL);
			CloseHandle(file);
		}
	}

	return result;
}

BOOL System::UnloadDll(__in const char* szLibName, __in DWORD procId)
{
	return UnloadDll(GetModuleAddress(szLibName, procId), procId);
}

BOOL System::UnloadDll(__in const HMODULE pUnloadDll, __in DWORD procId)
{
	HANDLE hProcess = NULL, hRemoteThread = NULL;
	PVOID kfl = NULL;
	DWORD dwFlag = 0;
	bool result = false;
	hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, procId);

	if(pUnloadDll && (hProcess!=INVALID_HANDLE_VALUE))
	{  
		kfl = GetProcAddress(GetModuleHandleA(KERNEL_DLL), "FreeLibrary");
		if (kfl)
		{ 
			hRemoteThread = CreateRemoteThread(hProcess, 0, 0,(LPTHREAD_START_ROUTINE)kfl, pUnloadDll, 0, &dwFlag);
			if(hRemoteThread)
			{
				result = TRUE;
				CloseHandle(hRemoteThread); //terminate thread ?!
			}
		}

		CloseHandle(hProcess);
	}

	return result;
}

// Loads libs in any system process
BOOL System::InjectModule(__in DWORD dwPiD, __in const char* szModule)
{
	HANDLE hProcess=NULL, hRemoteThread=NULL;
	PVOID pvDLL=NULL, pkf=NULL;
	DWORD pNBW=0, dwThId=0;
	BOOL result = false;

	hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, dwPiD);
	
	if(hProcess) {
		pvDLL = VirtualAllocEx(hProcess, NULL, kstrlen(szModule)+1, MEM_COMMIT, PAGE_READWRITE);
		if(pvDLL)
		{ 
			if(WriteProcessMemory(hProcess, pvDLL, (PVOID)szModule, kstrlen(szModule)+1, &pNBW))
			{
				pkf = GetProcAddress(GetModuleHandleA(KERNEL_DLL),"LoadLibraryA");

				if (pkf)
				{ 
					hRemoteThread = CreateRemoteThread(hProcess,0,0,(LPTHREAD_START_ROUTINE)pkf,pvDLL,0, &dwThId);
					if(hRemoteThread)
					{ 
						result = true;
						CloseHandle(hRemoteThread); 
					} 
				}
			}

			if(result)
				Sleep(2000);
			
			VirtualFreeEx(hProcess, pvDLL, 0, MEM_RELEASE);
		}
		CloseHandle(hProcess); 
	}
	
	return result;
}

DWORD System::Get_LoadCount(DWORD dwPid, PVOID pImageBase) const
{
	DWORD countLoad = 0;
	LDR_MODULE ldrModule;
	PLDR_MODULE pldrModule = GetPtr_LDR_MODULE(dwPid, pImageBase);

	if(pldrModule){
		if(ReadMemory(dwPid, pldrModule, &ldrModule, sizeof(LDR_MODULE)))
		{
			countLoad = ldrModule.LoadCount;
		}
	}

	return countLoad;
}

PLDR_MODULE System::GetPtr_LDR_MODULE(DWORD dwPid, PVOID pImageBase) const
{
	PEB peb, *ppeb = GetPtrPEB(dwPid);	// 1st level
	PEB_LDR_DATA ldrData;				// 2nd level
	LDR_MODULE first_ldr, current_ldr;	// 3rd level
	PLDR_MODULE ptrLdrModule = NULL;

	// Pointer to the structure in a different context
	PLDR_MODULE ptr_current_ldr = NULL;

	if(!ppeb)
		return NULL;

	// Saves PEB structure in the local variable
	if(!ReadMemory(dwPid, ppeb, &peb, sizeof(PEB)))
		return NULL;

	// Saves PEB_LDR_DATA structure in the local variable
	if(!ReadMemory(dwPid, peb.LdrData, &ldrData, sizeof(PEB_LDR_DATA)))
		return NULL;

	// first_ldr = *((LDR_MODULE *) ldrData.InLoadOrderModuleList.Flink);
	if(!ReadMemory(dwPid, ldrData.InLoadOrderModuleList.Flink, &first_ldr, sizeof(LDR_MODULE)))
		return NULL;

	// CurrentModule = FirstModule;
	current_ldr = first_ldr;
	ptr_current_ldr = (PLDR_MODULE)ldrData.InLoadOrderModuleList.Flink;

	do
	{
// 		if (_wcsicmp(CurrentModule.BaseDllName.Buffer, L"ntdll.dll") == 0)

		if(current_ldr.BaseAddress == pImageBase){
			ptrLdrModule = ptr_current_ldr;
			break;
		}

		ptr_current_ldr = (PLDR_MODULE)current_ldr.InLoadOrderModuleList.Flink;

		// current_ldr = *((LDR_MODULE *) current_ldr.InLoadOrderModuleList.Flink);
		if(!ReadMemory(dwPid, current_ldr.InLoadOrderModuleList.Flink, &current_ldr, sizeof(LDR_MODULE)))
			return NULL;

	} while (current_ldr.BaseAddress != first_ldr.BaseAddress);

	return ptrLdrModule;
}

PPEB System::GetPtrPEB(DWORD dwPid) const
{
	PROCESS_BASIC_INFORMATION pbi;
	ULONG lRetLen;
	HANDLE hProcess = 0;
	PPEB ptrPeb = NULL;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);

	if(!hProcess) {
		return NULL;
	}

	if (STATUS_SUCCESS == pfnNtQueryInformationProcess(hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof (PROCESS_BASIC_INFORMATION),
		&lRetLen))
	{
		ptrPeb = pbi.PebBaseAddress; 
	}

	CloseHandle(hProcess);
	return ptrPeb;
}

PVOID System::GetDriverImageBaseAddress(__in const char* szdrv, __in bool exact_match)
{
	ULONG status = 0;
	unsigned long i = 0;
	PVOID pImageBase = NULL;
	PSYSTEM_MODULE pdrv = NULL;
	PSYSTEM_MODULE_INFORMATION pmod_inf = NULL;
	unsigned long ulen = 0;

	status = pfnNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulen);

	if(ulen)
	{
		pmod_inf = (PSYSTEM_MODULE_INFORMATION)getmem(ulen);
		if(pmod_inf)
		{
			status = pfnNtQuerySystemInformation(SystemModuleInformation, pmod_inf, ulen, &ulen);
			if(!status)
			{
				for(i=0; i<=pmod_inf->ModulesCount; i++)
				{
					pdrv = &pmod_inf->Modules[i];
					if (exact_match)
					{
						if(kstrcmp((char*)(pdrv->Name+pdrv->NameOffset), szdrv)==0)
						{
							obj_found:
							pImageBase = pdrv->ImageBaseAddress;
							freemem(pmod_inf);
							return pImageBase;
						}
					} else {
						if(kstrstr((char*)(pdrv->Name+pdrv->NameOffset), szdrv) != 0){
							goto obj_found;
						}
					}
				}	
			}

			freemem(pmod_inf);
		}
	}

	return NULL;
}

BOOL System::GetDriverFilePath(__in PVOID pImageBase, __out char* pFilePath, __inout PDWORD pSize)
{
	unsigned long i = 0, ulen = 0;
	PSYSTEM_MODULE pdrv = NULL;
	PSYSTEM_MODULE_INFORMATION pmod_inf = NULL;
	BOOL written = false;

	ULONG status = pfnNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulen);

	if(ulen){
		pmod_inf = (PSYSTEM_MODULE_INFORMATION)getmem(ulen);
		if(pmod_inf)
		{
			status = pfnNtQuerySystemInformation(SystemModuleInformation, pmod_inf, ulen, &ulen);
			if(!status){
				for(i=0; i<=pmod_inf->ModulesCount; i++)
				{
					pdrv = &pmod_inf->Modules[i];
					if (pdrv->ImageBaseAddress == pImageBase)
					{
						ulong length = kstrlen((char*)&pdrv->Name[0]) + 1;
						if (written = (length <= (*pSize))){
							memcpy(pFilePath, pdrv->Name, length);
						}

						*pSize = length;
					}
				}	
			}

			freemem(pmod_inf);
		}
	}

	return written;
}

BOOL System::GetDriverFileName(__in PVOID pImageBase, __out char* pFile, __inout PDWORD pSize)
{
	unsigned long i = 0, ulen = 0;
	PSYSTEM_MODULE pdrv = NULL;
	PSYSTEM_MODULE_INFORMATION pmod_inf = NULL;
	BOOL written = false;

	ULONG status = pfnNtQuerySystemInformation(SystemModuleInformation, NULL, 0, &ulen);
	if(ulen){
		pmod_inf = (PSYSTEM_MODULE_INFORMATION)getmem(ulen);
		if(pmod_inf){
			status = pfnNtQuerySystemInformation(SystemModuleInformation, pmod_inf, ulen, &ulen);
			if(!status){
				for(i=0; i<=pmod_inf->ModulesCount; i++){
					pdrv = &pmod_inf->Modules[i];
					if (pdrv->ImageBaseAddress == pImageBase){
						ulong length = kstrlen((char*)((char*)pdrv->Name + pdrv->NameOffset)) + 1;
						if (written = (length <= (*pSize))){
							memcpy(pFile, pdrv->Name, length);
						}
						*pSize = length;
					}
				}	
			}
			freemem(pmod_inf);
		}
	}

	return written;
}

BOOL System::IsSpace(__in const HMODULE pImageBase, __in const PVOID pAddress)
{
	PIMAGE_NT_HEADERS32 pHeader = NULL;

	if(pImageBase)
	{
		pHeader = (PIMAGE_NT_HEADERS32)get_header_addr(pImageBase);
		if( ((DWORD)pImageBase < (DWORD)pAddress) && ((DWORD)pAddress < (DWORD)pImageBase + pHeader->OptionalHeader.SizeOfImage))
		{
			return TRUE;
		}
	}

	return FALSE;
}

void System::GetDbgPrivilege()
{
	HANDLE TTokenHd;
	TOKEN_PRIVILEGES TTokenPvg, rTTokenPvg;
	ULONG cbtpPrevious, pcbtpPreviousRequired;

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TTokenHd))
	{
		LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &TTokenPvg.Privileges[0].Luid); 
		TTokenPvg.PrivilegeCount = 1; 
		TTokenPvg.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
		cbtpPrevious = sizeof(rTTokenPvg); 
		pcbtpPreviousRequired = 0; 
		AdjustTokenPrivileges(TTokenHd, FALSE, &TTokenPvg, cbtpPrevious, &rTTokenPvg, &pcbtpPreviousRequired); 
	}
}

BOOL System::WriteMemory(__in DWORD dwPiD, __in const PVOID pAddress, __in const PVOID pWriteData, __in DWORD dwLength)
{
	DWORD protect, dwTmp;
	HANDLE hProcess = NULL;
	BOOL result = FALSE;
	
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPiD);

	if(hProcess)
	{
		if(VirtualProtectEx(hProcess, pAddress, dwLength, PAGE_READWRITE, &protect))
		{
			if(WriteProcessMemory(hProcess, pAddress, pWriteData, dwLength, &dwTmp))
			{
				if(VirtualProtectEx(hProcess, pAddress, dwLength, protect, &dwTmp))
				{
					result = TRUE;
				}
			}
		}
		CloseHandle(hProcess);
	}
	
	return result;
}

BOOL System::ReadMemory(__in DWORD dwPiD, __in const PVOID pAddress, __out const PVOID pBuffer, __in DWORD dwLength)
{
	DWORD protect, dwTmp;
	HANDLE hProcess = NULL;
	BOOL result = FALSE;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPiD);

	if(hProcess)
	{
		result = ReadProcessMemory(hProcess, pAddress, pBuffer, dwLength, &dwTmp);
		CloseHandle(hProcess);
	}

	return result;
}

BOOL GetPrivilege(char* SeNamePriv)
{
	HANDLE hToken;
	LUID lpLuid;
	TOKEN_PRIVILEGES  NewState;

	if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken))
	{
		if(LookupPrivilegeValue(NULL, SeNamePriv, &lpLuid))
		{
			NewState.PrivilegeCount = 1;
			NewState.Privileges[0].Luid = lpLuid;
			NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges (hToken, FALSE, &NewState, sizeof(NewState), NULL, NULL);
			return TRUE;
		}

		CloseHandle (hToken);
	}

	return FALSE;
}

void System::GetMaxPriv(void){

	int count = ((int)(sizeof privilages/sizeof privilages[0]));

	for(int i=0; i<count; i++)
		GetPrivilege(privilages[i].szPrivName);
}

HMODULE System::GetModuleAddress(__in const char* szLibName, __in DWORD dwPid, __in const PWinModules pModList)
{
	HMODULE result = NULL;
	PWinModules pModules = NULL;

	if(pModList)
	{
		pModules = pModList;
	} else
	{
		pModules = new WinModules();
		GetModules(dwPid, *pModules);
	}

	for(WinModules::const_iterator it = pModules->constBegin(); it != pModules->constEnd(); ++it)
		if(kstrcmp((*it)->szModule, szLibName)==0)
		{
			result = (HMODULE)(*it)->modBaseAddr;
			break;
		}

	if(!pModList)
	{
		Close(*pModules);
		delete pModules;
	}

	return result;
}

PVOID System::GetModuleBase(__in DWORD dwPid, __in const char* szModuleName, __in const PWinModules pModList)
{
	PVOID result = NULL;
	PWinModules pModules = NULL;

	if(pModList)
	{
		pModules = pModList;
	} else
	{
		pModules = new WinModules();
		GetModules(dwPid, *pModules);
	}

	for(WinModules::const_iterator it = pModules->constBegin(); it != pModules->constEnd(); ++it)
	{
		if(kstrcmp_Aa((*it)->szModule, szModuleName)==0)
		{
			result = (PVOID)(*it)->modBaseAddr;
			break;
		}
	}

	if(!pModList)
	{
		Close(*pModules);
		delete pModules;
	}

	return result;
}

PVOID System::GetModuleBase(__in DWORD dwPid, __in const char* szModuleName, __in const BYTE* pSpace, __in const PWinModules pModList)
{
	PVOID result = NULL;
	PWinModules pModules = NULL;

	if(pModList)
	{
		pModules = pModList;
	} else
	{
		pModules = new WinModules();
		GetModules(dwPid, *pModules);
	}

	for(WinModules::const_iterator it = pModules->constBegin(); it != pModules->constEnd(); ++it)
	{
		if((kstrcmp_Aa((*it)->szModule, szModuleName)==0) && 
			(((*it)->modBaseAddr <= pSpace) && (pSpace <= (*it)->modBaseAddr+(*it)->modBaseSize)))
		{
				result = (PVOID)(*it)->modBaseAddr;
				break;
		}
	}

	if(!pModList)
	{
		Close(*pModules);
		delete pModules;
	}

	return result;
}

BOOL System::GetModuleName(__in DWORD dwPid, __in PVOID pBaseAddr, __out char* szName, __in const PWinModules pModList)
{
	bool result = FALSE;
	PWinModules pModules = NULL;

	if(pModList)
	{
		pModules = pModList;
	} else
	{
		pModules = new WinModules();
		GetModules(dwPid, *pModules);
	}

	for(WinModules::const_iterator it = pModules->constBegin(); it != pModules->constEnd(); ++it)
		if((PVOID)(*it)->modBaseAddr == pBaseAddr)
		{
			//kmemcpy(szName, pmod->pdata->szModule, kstrlen(pmod->pdata->szModule)+1);
			kstrcpy(szName, (*it)->szModule);
			result = TRUE;
			break;
		}

	if(!pModList)
	{
		Close(*pModules);
		delete pModules;
	}

	return result;
}

// returns full address to a file of module on a disk
BOOL System::GetModuleFullName(__in DWORD dwPid, __in PVOID hLib, __out char* szLibName, __in const PWinModules pModList)
{
	bool result = FALSE;
	PWinModules pModules = NULL;

	if(pModList)
	{
		pModules = pModList;
	} else
	{
		pModules = new WinModules();
		GetModules(dwPid, *pModules);
	}

	for(WinModules::const_iterator it = pModules->constBegin(); it != pModules->constEnd(); ++it)
		if((HMODULE)(*it)->modBaseAddr == hLib)
		{
			kmemcpy(szLibName, (*it)->szExePath, kstrlen((*it)->szExePath)+1);
			result = TRUE;
			break;
		}

	if(!pModList)
	{
		Close(*pModules);
		delete pModules;
	}

	return result;
}

// Реализовтаь возможность проверки других адресных пространств
HMODULE System::GetModuleBase(__in PVOID pSpace, __in DWORD dwPid, __in const PWinModules pModList)
{
	HMODULE result = NULL;
	PWinModules pModules = NULL;

	if(pModList)
	{
		pModules = pModList;
	} else
	{
		pModules = new WinModules();
		GetModules(dwPid, *pModules);
	}

	for(WinModules::const_iterator it = pModules->constBegin(); it != pModules->constEnd(); ++it)
		if(((DWORD)(*it)->modBaseAddr<(DWORD)pSpace)&&((DWORD)pSpace<((DWORD)(*it)->modBaseAddr+(*it)->modBaseSize)))
		{
			result = (HMODULE)(*it)->modBaseAddr;
			break;
		}

	if(!pModList)
	{
		Close(*pModules);
		delete pModules;
	}

	return result;
}

// szFile - full address to a file
bool System::GetProcessName(__in DWORD dwPid, __out char* szFile, __in const PWinProcesses& processes)
{
	bool result = FALSE;
	PWinProcesses procList = NULL;

	if(processes)
	{
		procList = processes;
	} else
	{
		procList = new WinProcesses();
		GetProcesses(*procList);
	}

	for(WinProcesses::const_iterator it = procList->constBegin(); it != procList->constEnd(); ++it)
		if((*it)->th32ProcessID == dwPid)
		{
			//kmemcpy(szFile, proc->pdata->szExeFile, kstrlen(proc->pdata->szExeFile)+1);
			kstrcpy(szFile, (*it)->szExeFile);
			result = TRUE;
			break;
		}

	if(processes == NULL)
	{
		Close(*procList);
		delete procList;
	}

	return result;
}

DWORD System::GetProcessId(__in const char* szName, const PWinProcesses& processes)
{
	DWORD result = 0;
	PWinProcesses procList = NULL;

	if(processes)
	{
		procList = processes;
	} else
	{
		procList = new WinProcesses();
		GetProcesses(*procList);
	}

	for(WinProcesses::const_iterator it = procList->constBegin(); it != procList->constEnd(); ++it)
		if(kstrcmp((*it)->szExeFile, szName)==0)
		{
			result = (*it)->th32ProcessID;
			break;
		}

	if(!processes)
	{
		Close(*procList);
		delete procList;
	}

	return result;
}

// Сделать корректный список процессов и проверку на выделение памяти
void System::GetProcesses(__out WinProcesses& processes)
{
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe32;
	PPROCESSENTRY32 the_process = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if((hProcessSnap != INVALID_HANDLE_VALUE))
	{
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(hProcessSnap, &pe32))
		{
			do
			{
				the_process = (PPROCESSENTRY32)(getmem(sizeof(PROCESSENTRY32)));
				if(the_process)
				{
					kmemcpy((char*)the_process, (char*)&pe32, sizeof(PROCESSENTRY32));
					processes.push_front(the_process);
				}
				
			} while(Process32Next( hProcessSnap, &pe32));
		}
		CloseHandle( hProcessSnap );
	}
}

// разобраться с закрытием
void System::Close(__in WinProcesses& processes)
{
	for(WinProcesses::const_iterator it = processes.constBegin(); it != processes.constEnd(); ++it)
		freemem((PPROCESSENTRY32)(*it));

	processes.clear();
}

// то же самое
void System::Close(WinModules& modules)
{
	for(WinModules::const_iterator it = modules.constBegin(); it != modules.constEnd(); ++it)
		freemem((PMODULEENTRY32)(*it));

	modules.clear();
}

void System::GetModules( __in DWORD pid, __out WinModules& winMod)
{
	MODULEENTRY32 me32;
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	PMODULEENTRY32 the_module = NULL;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if(hModuleSnap != INVALID_HANDLE_VALUE)
	{
		me32.dwSize = sizeof(MODULEENTRY32);
		if(Module32First(hModuleSnap, &me32) )
		{
			do
			{
				the_module = (PMODULEENTRY32)(getmem(sizeof(MODULEENTRY32)));
				if(the_module)
				{
					kmemcpy((char*)the_module, (char*)&me32, sizeof(MODULEENTRY32));
					winMod.push_back(the_module);
				}

			} while(Module32Next(hModuleSnap, &me32)); //
		}
		CloseHandle(hModuleSnap);
	}
}

// Returns base address of module by pointer
PVOID System::MmImageBaseByPointer(__in DWORD pid, __in const PVOID p)
{
	PVOID pBaseRegion = 0, pImageBase = NULL;
	HANDLE proc = INVALID_HANDLE_VALUE;
	MEMORY_BASIC_INFORMATION meminf;

	proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	if(proc != INVALID_HANDLE_VALUE)
	{
		while(VirtualQueryEx(proc, pBaseRegion, &meminf, sizeof(meminf)))
		{
			if(meminf.Type == MEM_IMAGE)
			{
				if(meminf.BaseAddress <= p && (PBYTE)p <= ((PBYTE)meminf.BaseAddress+meminf.RegionSize))
				{
					pImageBase = meminf.AllocationBase;
					break;
				}
			}

			pBaseRegion = (PVOID)((PBYTE)pBaseRegion + meminf.RegionSize);
		}

		CloseHandle(proc);
	}

	return pImageBase;
}

PVOID System::MmGetModuleNameByPointer(__in DWORD pid, __in PVOID pAddr, __out char* pBuf, __in DWORD dwBuf_size)
{
	PVOID pLoadTo = MmImageBaseByPointer(pid, pAddr);

	if(pLoadTo)
	{
		HANDLE proc = INVALID_HANDLE_VALUE;
		proc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		if(proc != INVALID_HANDLE_VALUE)
		{
			if(!GetMappedFileNameA(proc, pLoadTo, pBuf, dwBuf_size))
				pLoadTo = NULL;

			CloseHandle(proc);
		}
	} 

	return pLoadTo;
}

QString System::gettime()
{
	return QString("11:23:34");
}

// Opens early created file or create a new empty file, with the following rights - read, write
HANDLE System::CreateOrOpen(const QString& filepath)
{
	HANDLE hfile = INVALID_HANDLE_VALUE;
	DWORD crflags = CREATE_NEW;

OPEN_EXISTING_FILE:

	hfile = CreateFileA(filepath.toAscii().constData(),
		GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ|FILE_SHARE_WRITE,
		NULL,
		crflags,
		0,
		NULL);

	if ((hfile == INVALID_HANDLE_VALUE) && (GetLastError() == ERROR_FILE_EXISTS))
	{
		crflags = OPEN_EXISTING;
		goto OPEN_EXISTING_FILE;
	}

	return hfile;
}

//end
