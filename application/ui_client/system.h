
//      (c)VsoftLab 2006 - 2014
//		Author: burluckij@gmail.com	


#ifndef SYSTEM_H
#define SYSTEM_H

#undef UNICODE

#include "WinTypes.h"
#include <QLinkedList.h>
#include <qstring.h>

#ifndef _PSAPI_H_
#include <Psapi.h>
#endif

#ifndef _INC_TOOLHELP32
#include <TlHelp32.h>
#endif


#pragma comment(lib, "psapi")
#define TICK_STEP 500


typedef QLinkedList<PMODULEENTRY32> WinModules, *PWinModules;
typedef QLinkedList<PPROCESSENTRY32> WinProcesses, *PWinProcesses;

namespace Memory
{
	PVOID getmem(size_t x);
	void freemem(PVOID x);
}

// Provides base functional set for working with OS
class System: protected CBase {
private:
	bool init_state;

	FPFN_NtQuerySystemInformation pfnNtQuerySystemInformation;
	FPFN_NtQueryInformationProcess	pfnNtQueryInformationProcess;
	BOOL NtInitSystemInformation();

public:

	static const DWORD noprocess = 0;

	static BOOL LoadDriver(__in const char* szService);
	static BOOL UnloadDriver(__in const char* szService);
	static BOOL CreateDriverService(__in DWORD dwInstallFlag, __in const char* szService, __in const char* szDriverFile);
	static DWORD GetPeb(__in DWORD dwPid);
	
	static bool WriteToFile(__in const char* szFile, __in const PVOID pData, __in DWORD dwSize, __in DWORD flagCreated);
	static void GetDbgPrivilege();
	static BOOL UnloadDll(__in const char*, __in DWORD);
	static BOOL UnloadDll(__in const HMODULE, __in DWORD);
	static QString gettime();
	static HANDLE CreateOrOpen(const QString& filepath);

	static void GetModules(__in DWORD pid, __out WinModules&);
	static HMODULE GetModuleAddress(__in const char*, __in DWORD, __in const PWinModules = NULL);
	static BOOL GetModuleName(__in DWORD, __in PVOID, __out char*, __in const PWinModules = NULL);
	static BOOL GetModuleFullName(__in DWORD, __in PVOID, __out char*, __in const PWinModules = NULL);
	static HMODULE GetModuleBase(__in PVOID,__in DWORD, __in const PWinModules = NULL);
	static PVOID GetModuleBase( __in DWORD dwPiD, __in const char* szName, __in const PWinModules = NULL);
	static PVOID GetModuleBase(__in DWORD dwPiD, __in const char* szModuleName, __in const BYTE* pSpace, __in const PWinModules = NULL);
	static PVOID MmGetModuleNameByPointer(__in DWORD pid, __in PVOID pAddr, __out char* pBuf, __in DWORD dwBuf_size);
	static void Close(__in WinModules& plist);

	static BOOL InjectModule(__in DWORD, __in const char*);
	static BOOL ReadMemory(__in DWORD dwPiD, __in const PVOID pAddress, __out const PVOID pBuffer, __in DWORD dwLength);
	static BOOL WriteMemory(__in DWORD dwPiD, __in const PVOID pAddress, __in const PVOID pWriteData, __in DWORD dwLength);
	static void GetMaxPriv();
	static BOOL IsSpace(__in const HMODULE, __in const PVOID);

	static void GetProcesses(__out WinProcesses& processes);
	static DWORD GetProcessId(__in const char*, __in const PWinProcesses& = NULL);
	static bool GetProcessName(__in DWORD, __out char*, __in const PWinProcesses& = NULL);
	static void Close(__in WinProcesses& processes);
	
	static void PrintHideDll(__in DWORD pid);
	static PVOID MmImageBaseByPointer(__in DWORD pid, __in const PVOID p);

	// These functions provides access to the main structures of the system
	PPEB GetPtrPEB(DWORD dwPid) const;
	PLDR_MODULE GetPtr_LDR_MODULE(DWORD dwPid, PVOID pImageBase) const;
	DWORD Get_LoadCount(DWORD dwPid, PVOID pImageBase) const;

	PVOID GetDriverImageBaseAddress(__in const char*, __in bool exact_match = TRUE);
	BOOL GetDriverFilePath(__in PVOID pImageBase, __out char* pFilePath, __inout PDWORD pSize);
	BOOL GetDriverFileName(__in PVOID pImageBase, __out char* pFile, __inout PDWORD pSize);

	System(){
		init_state = NtInitSystemInformation();
	}

	bool State() const {
		return init_state;
	}
};

#endif // SYSTEM_H

//
