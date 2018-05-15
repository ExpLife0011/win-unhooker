//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com							

//#include "Security.h"
#include "Window.h"

using namespace Memory;

// The func validates the suspected object and then determinate - Is it the bad object?
BOOL Security::SendHookInfo(const PeFile* pAnalizeFile, const PeFile* pLibShot, PIMPORT_LIB plib, PIMPORT_FN pfn, PEXPORT_FN pExport)
{
	char tmp_cmp[MAX_PATH];
	HMODULE ptrInjectedModuleBase = NULL;
	bool use_hiding = FALSE;
	DWORD pid = pAnalizeFile->Pid();
	PIAT_HOOK rtk_inf = (PIAT_HOOK)getmem(sizeof(IAT_HOOK));

	if(!rtk_inf)
		return false;

	System::GetProcessName(pid, rtk_inf->szProc);
	System::GetModuleFullName(pid, pAnalizeFile->GetBaseX(), rtk_inf->szModule);
	ptrInjectedModuleBase = System::GetModuleBase(pfn->Api, pid);

	use_hiding = (ptrInjectedModuleBase == NULL);

	// Hidden interceptor. The module file is hidden in memory
	if(use_hiding)
	{ 
		// Find base address of hidden module. Seeks the file mapping in memory
		ptrInjectedModuleBase = (HMODULE)System::MmGetModuleNameByPointer(pid, pfn->Api, rtk_inf->szHookLibrary, MAX_PATH);

		// Its a very powerful thing! I can't find it now.
		if(!ptrInjectedModuleBase)
		{
			wsprintfA(rtk_inf->szHookLibrary, "unknown");
			// forgot to free memory
		}

	} else  
	{
		// Simple interceptor, I can get file path.
		System::GetModuleFullName(pid, ptrInjectedModuleBase, rtk_inf->szHookLibrary);

		// Address of interceptor was detected, Is it features of win7 import?
		if(pLibShot->GetBaseX() == ptrInjectedModuleBase)
		{
			freemem(rtk_inf);
			return TRUE;
		}
	}

	// Collect and save info about the interceptor
	rtk_inf->pid = pid;
	rtk_inf->hideObject = use_hiding;
	rtk_inf->piat = pfn->AddrFuncAddr;
	rtk_inf->originalApiAddr = pExport->Api;
	rtk_inf->pHookCall = pfn->Api;
	kstrcpy(rtk_inf->szApiName, pfn->ApiName);
	kstrcpy(rtk_inf->szLibName, plib->szLib);

// 	PINTERCEPTOR hookInfo = (PINTERCEPTOR)getmem(sizeof(INTERCEPTOR));
// 	hookInfo->type = IAT_INTERCEPTOR;
// 	hookInfo->pInfo = rtk_inf;

	// Tree of malware objects will build ui_client
	emit foundWinApiHook((IAT_HOOK*)rtk_inf);

	// in own process need delete all interceptions
	if(pid == GetCurrentProcessId())
	{
		DWORD realaddress = (DWORD)rtk_inf->originalApiAddr;
		System::WriteMemory(GetCurrentProcessId(), pfn->AddrFuncAddr, &realaddress, sizeof(realaddress));
	}

	return TRUE;
}

// note(!): have to improve and do deep research of this func
// Looks up interceptors in import application table (IAT) 
void Security::Hooks3(HMODULE pModule, DWORD pid, ModuleImage& pe_dlls)
{
	const PeFile* peInfoOfModule = Contain(pe_dlls, (DWORD)pModule), *pExportedLib = NULL;
	WinModules procModules;
	PEXPORT_FN pExportFn = NULL;
	PIMPORT_LIB pImportsLib = NULL;
	ULONG impdlls = 0;
	PVOID pImageBase_LibExport = NULL;

	System::GetModules(pid, procModules);

	if(procModules.isEmpty())
		return;
	
	if(peInfoOfModule && (peInfoOfModule->GetError() == SUCCESS_INIT))
	{
		pImportsLib = peInfoOfModule->GetImport(&impdlls);

		// Enumerate all libs with imported functions
		for(ulong i = 0; i<impdlls; i++, pImportsLib++)
		{
			// Compares: Is it the system library?
			if(ScanOnlyProtectedLibs && !ContainsProtectedLib(pImportsLib->szLib))
				continue;	

			// note(!): in the process can be loaded many libraries with the same name
			// In case of this fact, I have to seek the library by name and by pointer,
			// which points to the some memory region - 0x_func, condition: 0x_base_addr >= 0x_func >= 0x_end
			pImageBase_LibExport = System::GetModuleBase(pid, pImportsLib->szLib,(BYTE*)pImportsLib->functions->Api, &procModules);

			// The library was hidden?
			// (0) there need to improve hidden detection
			if(pImageBase_LibExport == NULL)
			{
				pImageBase_LibExport = System::GetModuleBase(pid, pImportsLib->szLib, &procModules);
			}

			// продумать функцию для корректного снятия перехватчика т.к. возможно восстановление
			// адреса функции на 'родственную' библиотеку с тем  же именем но! в другой директории.

			// enumerate all functions
			for(PIMPORT_FN pFunc = pImportsLib->functions; pFunc != NULL; pFunc=pFunc->next)
			{
				// Searching the module in the list, by ADDRESS.
				// Searching by ADDRESS is used because can be collisions in a searching
				// by names ( In one process can be loaded several libraries with the same names ).

				pExportedLib = Contain(pe_dlls, (DWORD)pImageBase_LibExport);
				if(!pExportedLib)
				{
					// Print to scan log
					continue;
				}

				// Gets info about func by export table
				if((pExportFn = pExportedLib->GetExportedFnInfo(pFunc->ApiName)) == NULL)
				{
					continue;
				}

				// If addresses are not equal and it is not a forwarding mechanism this is a interception!
				if((pFunc->Api != pExportFn->Api) && !pExportFn->forward_)
				{
					// Skip some .net features
					// First of all I have to skip entry point
					// and so on ...
					BOOL dotNetEntryPoint = kstrcmp(pExportFn->Name, DOT_NET_ENTRY_POINT) == 0;

					if(!dotNetEntryPoint)
					{
						SendHookInfo(peInfoOfModule, pExportedLib, pImportsLib, pFunc, pExportFn);
						m_countBadObjects++; // !!!
					}
				}
			}
		}
	}

	System::Close(procModules);
}
