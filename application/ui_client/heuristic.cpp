
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#include "heuristic.h"
#include <string.h>

//typedef unsigned short u_short;

// BOOL LookupImpFn(const PeFile* peFile, __in const char* szLib, __in const char* szFnName)
// {
// 	ulong m_length = 0;
// 	PIMPORT_LIB plib = peFile->GetImport(&m_length);
// 
// 	for(ulong i = 0; i<m_length; i++, plib++){
// 		if(CBase::kstrstr(plib->szLib, szLib) != NULL){
// 			for(PIMPORT_FN pfn = plib->functions; pfn != NULL; pfn = pfn->next){
// 				if(CBase::kstrstr(pfn->ApiName, szFnName) != NULL) {
// 					return TRUE;
// 				}
// 			}
// 		}
// 	}
// 
// 	return FALSE;
// }

BOOL LookupImpFn(__in const PeFile* peFile, __in const char* szLib, __in const char* szFnName)
{
	ulong m_length = 0;
	PIMPORT_LIB plib = peFile->GetImport(&m_length);
	//QString libName_lower = QString(szLib).toLower();
	//QString fnName_lower = QString(szFnName).toLower();

	int libName_length = CBase::kstrlen(szLib);
	int fnName_length = CBase::kstrlen(szFnName);

	if(!szFnName || !szLib)
	{
		MessageBoxA(0,"ss","s", 0);
	}

	// I use _strnicmp without locales because all what I compare
	// it's system functions, libraries. They all are in English

	// Enumerate imported libs
	for(ulong i = 0; i<m_length; i++, plib++)
	{
		if(plib->szLib && (strnicmp(plib->szLib, szLib, libName_length) == 0))
		{
			for(PIMPORT_FN pfn = plib->functions; pfn != NULL; pfn = pfn->next)
			{
				if(!pfn->Ordinal && pfn->ApiName)
				{
					if(_strnicmp(pfn->ApiName, szFnName, fnName_length) == 0){
						return TRUE;
					}
				}
			}
		}
	}

	return FALSE;
}

u_short LookupInfected(const PeFile* peFile)
{
	return 0;
}

u_short LookupDownloading(const PeFile* peFile)
{
	u_short downloading = 0, execfunc = 0, creating = 0;

	downloading = LookupImpFn(peFile, URLMON_DLL, Txt_UrlDownloadToFile);
	execfunc = LookupImpFn(peFile, SHELL_DLL, Txt_ShellExecute) ||
		LookupImpFn(peFile, KERNEL_DLL, Txt_WinExec) ||
		LookupImpFn(peFile, KERNEL_DLL, Txt_CreateProcess) ||
		LookupImpFn(peFile, ADVAPI_DLL, Txt_CreateProcessAsUser);

	//LookupImpFn(peFile, , );

	return downloading && execfunc;
}

u_short LookupSysRegistration(const PeFile* peFile)
{
	return 0;
}

u_short LookupUsingPrivilages(const PeFile* peFile)
{
	u_short sys_privilages = LookupImpFn(peFile, ADVAPI_DLL, Txt_AdjustTokenPrivileges) &&
		LookupImpFn(peFile, ADVAPI_DLL, Txt_OpenProcessToken) && 
		LookupImpFn(peFile, ADVAPI_DLL, Txt_LookupPrivilegeValue);

	return sys_privilages;
}

u_short LookupKeyLogger(const PeFile* peFile)
{
	return 0;
}

u_short LookupClipboardSpy(const PeFile* peFile)
{
	return 0;
}

bool HeurGetDescription(__out PHEUR_FILE_DESCR pDescr, const PeFile* peFile)
{
	bool built_descr = true;

	pDescr->entries[Infected] = LookupInfected(peFile);
	pDescr->entries[Downloader] = LookupDownloading(peFile);
	pDescr->entries[UsePrivilages] = LookupUsingPrivilages(peFile);
	pDescr->entries[ClipboardSpy] = LookupClipboardSpy(peFile);
	pDescr->entries[KeyLogger] = LookupKeyLogger(peFile);
	pDescr->entries[SysRegistration] = LookupSysRegistration(peFile);
	pDescr->entries[AvKiller] = 0;
	pDescr->entries[NoDigitalSign] = 0;

	return built_descr;
}

bool HeurGetDescription(__out PHEUR_FILE_DESCR pDescr, QString filePath)
{
	PeFile file(filePath.toAscii().constData());

	if(file.GetError())
		return false;

	return HeurGetDescription(pDescr, (const PeFile*)&file);
}

// enum HeuristicClassification  {
// 	SysRegistration = 0,
// 	Downloader,
// 	Infected,
// 	UsePrivilages,
// 	AvKiller,
// 	ClipboardSpy,
// 	KeyLogger,
// 	NoDigitalSign
// };

QString HeurGetDescription(__in const HEUR_FILE_DESCR* pObjectDescription)
{
	QString description;

	if(pObjectDescription)
	{
		if (pObjectDescription->entries[SysRegistration])
			description += " SystemRegistrator";

		if (pObjectDescription->entries[Downloader])
			description += " Downloader";

		if (pObjectDescription->entries[Infected])
			description += " Infected";

		if (pObjectDescription->entries[AvKiller])
			description += " AvKiller";

		if (pObjectDescription->entries[UsePrivilages])
			description += " UsePrivilages";

		if (pObjectDescription->entries[ClipboardSpy])
			description += " ClipboardSpy";

		if (pObjectDescription->entries[KeyLogger])
			description += " KeyLogger";

		if (pObjectDescription->entries[NoDigitalSign])
			description += " NoDigitalSign";
	}

	return description;
}
