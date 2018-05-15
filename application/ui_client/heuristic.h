
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014


#ifndef HEURISTIC_H
#define HEURISTIC_H

#include "pe.h"

#define KERNEL_DLL		"kernel32.dll"
#define USER_DLL		"user32.dll"
#define ADVAPI_DLL		"advapi32.dll"
#define SHELL_DLL		"shell32.dll"
#define NTDLL_DLL		"ntdll.dll"
#define URLMON_DLL		"urlmon.dll"
#define WININET_DLL		"wininet.dll"

#define Txt_UrlDownloadToFile		"URLDownloadToFile"
#define Txt_WinExec					"WinExec"
#define Txt_ShellExecute			"ShellExecute"
#define Txt_DeleteFile				"DeleteFile"
#define Txt_CopyFile				"CopyFile"
#define Txt_CopyFileEx				"CopyFileEx"
#define Txt_SetFileAttributes		"SetFileAttributes"
#define Txt_SetFilePointer			"SetFilePointer"
#define Txt_SetFilePointerEx		"SetFilePointerEx"
#define Txt_WriteFile				"WriteFile"
#define Txt_WriteFileEx				"WriteFileEx"
#define Txt_ReadFile				"ReadFile"
#define Txt_ReadFileEx				"ReadFileEx"
#define Txt_CreateProcess			"CreateProcess"
#define Txt_CreateProcessAsUser		"CreateProcessAsUser"
#define Txt_GetCurrentDirectory		"GetCurrentDirectory"
#define Txt_GetModuleFileName		"GetModuleFileName"
#define Txt_GetSystemDirectory		"GetSystemDirectory"
#define Txt_GetWindowsDirectory		"GetWindowsDirectory"
#define Txt_OpenProcessToken		"OpenProcessToken"
#define Txt_LookupPrivilegeValue	"LookupPrivilegeValue"
#define Txt_AdjustTokenPrivileges	"AdjustTokenPrivileges"
#define Txt_RegOpenKey				"RegOpenKey"
#define Txt_RegOpenKeyEx			"RegOpenKeyEx"
#define Txt_RegCreateKey			"RegCreateKey"
#define Txt_RegCreateKeyEx			"RegCreateKeyEx"
#define Txt_RegSetValue				"RegSetValue"
#define Txt_RegSetValueEx			"RegSetValueEx"

#define HEUR_CHARACTERISTIC_SIZE	8

enum HeuristicClassification  {
	SysRegistration = 0,
	Downloader = 1,
	Infected = 2,
	UsePrivilages = 3,
	AvKiller = 4,
	ClipboardSpy = 5,
	KeyLogger = 6,
	NoDigitalSign = 7
};


// File description by heuristic module
typedef struct HEUR_FILE_DESCR_
{
	ulong version;
	u_short entries[HEUR_CHARACTERISTIC_SIZE];
	// .. 
}HEUR_FILE_DESCR, *PHEUR_FILE_DESCR;

QString HeurGetDescription(__in const HEUR_FILE_DESCR* pObjectDescription);

// 
bool HeurGetDescription(__out PHEUR_FILE_DESCR, const PeFile* peFile);
bool HeurGetDescription(__out PHEUR_FILE_DESCR, QString filePath);

#endif
