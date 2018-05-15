
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#ifndef SECURITY_H
#define SECURITY_H

#include <QtGui/QMainWindow>
#include <qthread.h>
#include <QLinkedList.h>
#include <QMap.h>
#include <QSet.h>
#include "System.h"
#include "RefObject.h"
#include "pe.h"
#include "heuristic.h"
#include "client0.h"
#include "worklog.h"

typedef QMap<DWORD, PeFile*> ModuleImage;
typedef QSet<QString>	SetStr;
typedef QSet<QString>	TrustedApps;

#define RUN_SCAN				"Scan started: search hooks, hide dll's"
#define DOT_NET_LIB				"mscoree.dll"
#define DOT_NET_ENTRY_POINT		"_CorDllMain"

#define STOP_SECURITY_0 0x01

typedef struct ModuleList {
	ModuleList* pnext;
	PeFile* data;
}ModuleList, *PPEFiles;

typedef struct ANSI_STR{
	char name[MAX_PATH];
	int length;
	ulong hash;
}ANSI_STR, *PANSI_STR;

class Security: public QThread, protected CBase
{
	Q_OBJECT
private:
	//client0* m_client;
	BOOL ScanOnlyProtectedLibs;
	bool m_g_FastMode;
	bool m_threadEnable;
	bool m_useHeuristic;
	bool m_useWinApiHooks;
	bool m_recoverySsdt;

	// Set with trusted applications
	TrustedApps m_trustedApps;

	// Set of names protected libraries 
	SetStr m_iat_libs;

	mutable CRITICAL_SECTION m_csec0_protectedLibs;
	mutable CRITICAL_SECTION m_cs_trustedApps;

	HANDLE m_hThread;
	DWORD m_currentPid;

	// Speaks to use global searching
	volatile bool m_g_Scan;

	// Counter of founded suspicious objects
	int m_countBadObjects;
	int m_objectsScanned;
	
	char m_g_InfoAbObject[512];
	bool ScannerState() const;
	
	void CreateImages(__in DWORD pid, __out ModuleImage& chache);
	void DelstroyImages(__in ModuleImage&);
	PeFile* Contain(__in const ModuleImage& pModules, __in DWORD pImageBase) const;
	
	bool IsProcess(char*);

	// Starts searching hidden objects in kernel mode space
	void LookupHiddenProcess();

	// Searches hooks in SSDT
	void LookupSsdtHooks();

	// 
	BOOL SendHookInfo(const PeFile* pAnalizeFile, const PeFile* pLibShot, PIMPORT_LIB plib, PIMPORT_FN pfn, PEXPORT_FN pExport);

public:
	
	// The main procedure which starts to work right after thread creation.
	void run();

	// It's system security scanner.
	void Start();

	// Terminates procedure of searching malware objects.
	void Stop();

	// Suspends execution of the current thread (the main thread of security scanner).
	void Suspend();

	// Resumes execution of the current thread (the main thread of security scanner).
	void Resume();

	// Returns status of the main security's thread (true if it's running, otherwise false).
	bool Running() const;

	// Count of scanned objects
	ulong ObjectsScanned() const;

	// Adds new library to the protected libraries list
	void AddProtectedIAT(__in const QString& libName);

	// Contains library in the list of protected libraries
	bool ContainsProtectedLib(__in const char*) const;

	// Removes library form the protected libraries list
	void RemoveProtectedLib(__in const char* szLib);

	// Returns true if the set contains the trusted application; otherwise returns false.
	bool TrustedApplication(const QString& filePath) const;

	// Looks up interceptors in import application tables (IAT) of certain
	// module by pointer to Image Base Address (pModule) in the process (pid)
	void Hooks3(HMODULE pModule, DWORD pid, ModuleImage& plist);

	// Looks up suspicious activity in loaded file (process, dll)
	void HeurLookup(PVOID pImageBase, DWORD pid, PeFile* peFile);

	Security(bool heuristic = true, bool hooks_srch = true);
	~Security();

	bool RecoverySsdt(){
		return m_recoverySsdt;
	}

	void RecoverySsdt(bool val){
		m_recoverySsdt = val;
	}

	void EnableLookupApiHooks(bool flag);

signals:
	void foundWinApiHook(const IAT_HOOK*);
	void foundSsdtHook(const SSDT_HK*);
	void foundHiddenProccess(const CL0_PROC_INFO*);
	void foundHeurObject(QString, const HEUR_FILE_DESCR*);
	void foundHiddenObject(QString);
	void changedStatus(QString);
	void changedProgress(int);
	void sendMsg(long);
};

#endif
