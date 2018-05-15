
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014


//#include "Security.h"
#include "Window.h"

using namespace Memory;


Security::Security(bool heuristic, bool hooks_srch):
	m_countBadObjects(0),
	m_objectsScanned(0),
	m_g_Scan(true),
	m_useHeuristic(heuristic),
	m_useWinApiHooks(hooks_srch),
	m_hThread(INVALID_HANDLE_VALUE),
	m_threadEnable(false),
	m_recoverySsdt(false)
{
	InitializeCriticalSection(&m_csec0_protectedLibs);
	InitializeCriticalSection(&m_cs_trustedApps);

	EnableLookupApiHooks(FALSE);

	//"G:\\CyberPeace\\client0\\Win7Debug\\client0.sys"
	//"D:\\client0.sys"
	client0& client = client0::GetClient("G:\\CyberPeace\\client0\\Win7Debug\\client0---.sys", "client0");

	bool drvLoaded = client0::InstallAndLoad(client);
	if(drvLoaded)
	{
		WorkLog::GetLog().printmain("anti-rootkit driver was loaded successfully");

		if(client.InitDriver())
		{
			WorkLog::GetLog().printmain("anti-rootkit driver was configured successfully");
		} else {
			WorkLog::GetLog().printmain("error: anti-rootkit driver wasn't configured");
		}
	} else {
		WorkLog::GetLog().printmain("error: anti-rootkit driver wasn't loaded"); 
	}
}

ulong strhash(const char* sz, ulong len)
{
	ulong hash = 0;

	for(ulong i=0; i<len; i++)
		hash += (sz[i] + (sz[i]%10)*i + i);

	return hash;
}

// All strings are processed in lowercase
bool Security::ContainsProtectedLib(const char* szModule) const
{
	bool present = FALSE;

	EnterCriticalSection(&m_csec0_protectedLibs);
	present = m_iat_libs.contains(QString(szModule).toLower());
	LeaveCriticalSection(&m_csec0_protectedLibs);

	return present;
}

void Security::AddProtectedIAT(const QString& libName)
{
	bool present = m_iat_libs.contains(libName);

	if(!present)
	{
		EnterCriticalSection(&m_csec0_protectedLibs);
		m_iat_libs.insert(libName);
		LeaveCriticalSection(&m_csec0_protectedLibs);
	}
}

void Security::RemoveProtectedLib(const char* szLibName)
{
	EnterCriticalSection(&m_csec0_protectedLibs);
	m_iat_libs.remove(QString(szLibName).toLower());
	LeaveCriticalSection(&m_csec0_protectedLibs);
}

bool Security::TrustedApplication(const QString& filePath) const
{
	bool present = FALSE;

	EnterCriticalSection(&m_cs_trustedApps);
	present = m_trustedApps.contains(QString(filePath).toLower());
	LeaveCriticalSection(&m_cs_trustedApps);

	return present;
}

bool Security::IsProcess(char*)
{
	return TRUE;
}

void Security::CreateImages(__in DWORD pid, __inout ModuleImage& chache)
{
	PeFile* pobj = NULL;
	WinModules procModules;
	System::GetModules(pid, procModules);

	for(WinModules::const_iterator it = procModules.constBegin(); it != procModules.constEnd(); ++it)
	{
		// Load base information about file, without info about sections
		// note(!): need to know status of the process - killed, alive.
		// .. skip all killed processes
		pobj = new PeFile((*it)->modBaseAddr, pid, SECTION_ERROR);

		if(pobj->GetError() == SUCCESS_INIT)
			chache.insert((DWORD)pobj->GetBaseX(), pobj);
		else
			delete pobj;
	}

	System::Close(procModules);
}

void Security::LookupSsdtHooks()
{
	THooksSsdt hooks;

	if (!client0::GetClient().GetSsdtHooks(hooks))
	{
		WorkLog::GetLog().printmain("error: !m_client->GetSsdtHooks");
		return;
	}

	for(THooksSsdt::iterator hook = hooks.begin(); hook != hooks.end(); ++hook)
	{
		char srch_txt[] = "\\??\\";
		if (kstrstr(hook->rtkfile, srch_txt) != NULL){
			memcpy((void*)hook->rtkfile, ((char*)hook->rtkfile + kstrlen(srch_txt)), kstrlen(hook->rtkfile)-kstrlen(srch_txt)+1);
		}

		emit foundSsdtHook(&(*hook));
		//emit foundHiddenObject(QString(hook->rtkfile));

		if(m_recoverySsdt)
		{
			// reset hook
		}

		//continue;
	}
}

void Security::LookupHiddenProcess()
{
	WinProcesses processes;
	TSysProcesses proc_by_krnl;
	System::GetProcesses(processes);
	
	if (!client0::GetClient().GetRunningProcesses(proc_by_krnl))
	{
		WorkLog::GetLog().printmain("error: !m_client->GetRunningProcesses(proc_by_krnl)");
		return;
	}

	for(TSysProcesses::iterator krnl_proc = proc_by_krnl.begin();
		krnl_proc != proc_by_krnl.end(); ++krnl_proc)
	{
		bool hidden_proc = true;
		for(WinProcesses::const_iterator proc = processes.constBegin();
			proc != processes.constEnd() && this->ScannerState(); ++proc)
		{
			if((*proc)->th32ProcessID == krnl_proc->pid)
			{
				hidden_proc = false;
				break;
			}
		}

		if (hidden_proc)
		{
			// emit signal with found hidden object
			QString szfile = QString("%1").arg(krnl_proc->fileName);
			emit foundHiddenObject(szfile);
		}
	}

	System::Close(processes);
}

// Main procedure - malware scanner
void Security::Start()
{
	ModuleImage imagesModules;
	WinProcesses processes;
	WinModules procModules;

	LookupSsdtHooks();
	LookupHiddenProcess();

	// Load info about all system processes
	System::GetProcesses(processes);
	int act_proc = processes.count(), scanned_proc = 1;
	this->m_g_Scan = TRUE;

	// enumerate all system processes while g_Scan is TRUE
	for(WinProcesses::const_iterator it_proc = processes.constBegin();
		it_proc !=processes.constEnd() && this->ScannerState(); ++it_proc, scanned_proc++)
	{
		emit changedProgress(((scanned_proc*100.0) / act_proc));

		//
		CreateImages((*it_proc)->th32ProcessID, imagesModules);
		if(imagesModules.empty())
			continue;

		// Get list of modules in the 'current' process
		System::GetModules((*it_proc)->th32ProcessID, procModules);

		for(WinModules::const_iterator it = procModules.constBegin();
			it != procModules.constEnd(); ++it)
		{
			// InterlockedIncrement(..)
			m_objectsScanned++;

			// Send current information
			wsprintfA(m_g_InfoAbObject, "%s : %s", (*it_proc)->szExeFile, (*it)->szModule);
			emit changedStatus(m_g_InfoAbObject);

			// Hooks searcher
			if(m_useWinApiHooks){
				Hooks3((HMODULE)(*it)->modBaseAddr, (*it_proc)->th32ProcessID, imagesModules);
			}


			// Heuristic analyzer
			if (m_useHeuristic){
				PeFile* peFile = Contain(imagesModules, (DWORD)(*it)->modBaseAddr);
				HeurLookup((*it)->modBaseAddr, (*it_proc)->th32ProcessID, peFile);
			}
		}

		System::Close(procModules);
		DelstroyImages(imagesModules);
	}

	// Building and sending information about scanning
	if(m_countBadObjects)
	{
		wsprintfA(m_g_InfoAbObject, "Warning! Malware objects: %d", m_countBadObjects);
		emit changedStatus(m_g_InfoAbObject);
	} else
	{
		// if system is clean
		emit changedStatus(QObject::tr("System is clean"));
	}

	System::Close(processes);
}

void Security::HeurLookup(PVOID pImageBase, DWORD pid, PeFile* peFile)
{
	HEUR_FILE_DESCR heurDescr;
	memset(&heurDescr, 0, sizeof(heurDescr));

	if (!peFile){
		return;
	}

	HeurGetDescription(&heurDescr, peFile);
	//QScopedPointer<HEUR_FILE_DESCR> data(new HEUR_FILE_DESCR(heurDescr));

	for(int i = 0; i < HEUR_CHARACTERISTIC_SIZE; ++i)
	{
		if(heurDescr.entries[i])
		{
			emit foundHeurObject(QString(peFile->GetFilePath()), &heurDescr);
			break;
		}
	}
}

PeFile* Security::Contain(__in const ModuleImage& Modules, __in DWORD pImageBase) const
{
	return Modules.value(pImageBase, NULL);
}

void Security::run()
{
	m_threadEnable = TRUE;
	m_hThread = OpenThread(THREAD_ALL_ACCESS, 0, GetCurrentThreadId());
	this->Start();
	m_threadEnable = FALSE;

	// Sends massage to UI thread when searching was finished 
	emit sendMsg(STOP_SECURITY_0);
}

void Security::DelstroyImages(ModuleImage& p)
{
	ModuleImage::iterator it = p.begin(),it_end = p.end();

	for(; it != it_end; ++it){
		delete it.value();
	}

	p.clear();
}

bool Security::Running() const
{
	return m_threadEnable;
}

void Security::Stop()
{
	m_g_Scan = FALSE;
}

void Security::Suspend()
{
	m_threadEnable = FALSE;
	SuspendThread(m_hThread);
}

bool Security::ScannerState() const
{
	return m_g_Scan;
}

ulong Security::ObjectsScanned() const
{
	return m_objectsScanned;
}

void Security::Resume()
{
	m_threadEnable = TRUE;
	ResumeThread(m_hThread);
}

void Security::EnableLookupApiHooks(bool flag)
{
	ScanOnlyProtectedLibs = flag;
}

Security::~Security()
{
	if(client0::GetClient().UnloadDriver())
	{
		WorkLog::GetLog().printmain("Anti-Rootkit driver was unloaded successfully");

		if(client0::GetClient().DeleteService() == FALSE){
			WorkLog::GetLog().printmain("error: Anti-Rootkit driver wasn't deleted from system services");
		} else {
			WorkLog::GetLog().printmain("Anti-Rootkit driver was deleted from system");
		}
	} else {
		WorkLog::GetLog().printmain("Anti-Rootkit driver wasn't unloaded");
	}

	DeleteCriticalSection(&m_cs_trustedApps);
	DeleteCriticalSection(&m_csec0_protectedLibs);
}
