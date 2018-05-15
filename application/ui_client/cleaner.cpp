
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#include "Cleaner.h"
#include "RefObject.h"



BOOL Cleaner::UnloadObject(__in const char* szFilePath)
{
	bool unloaded = true;
	WinProcesses sysprss;
	System::GetProcesses(sysprss);

	WinProcesses::iterator end = sysprss.end();

	// Enumerate all system processes
	for(WinProcesses::iterator p_iter = sysprss.begin(); p_iter != end; ++p_iter)
	{
		// Compare object name with name of process.
		// If it's a process - just have to terminate it

		if (kstrcmp((*p_iter)->szExeFile, szFilePath) == 0)
		{
			HANDLE hproc = OpenProcess(PROCESS_TERMINATE, false, (*p_iter)->th32ProcessID);
			if(!hproc){
				unloaded = false;
				break;
			}

			unloaded = TerminateProcess(hproc, 0);
			CloseHandle(hproc);
			if (!unloaded) break;

		} else
		{
			// If it isn't the process - enumerate all its modules and
			// try to find lib with the same name

			WinModules m;
			System::GetModules((*p_iter)->th32ProcessID, m);
			for(WinModules::const_iterator m_i = m.constBegin(); m_i != m.constEnd(); ++m_i)
			{
				// Unloading mechanism
				if(kstrcmp((*m_i)->szExePath, szFilePath) == 0)
				{
					DWORD loadCount = m_sys.Get_LoadCount((*m_i)->th32ProcessID, (PVOID)(*m_i)->modBaseAddr);
					
					// If call has failed, may be it's a hidden object
					// I have to send the message to worklog
					if(!loadCount)
					{
						WorkLog::GetLog().printmain(QString("Couldn't get loadCount value of the %1 in pid %2")
							.arg(szFilePath)
							.arg((*m_i)->th32ProcessID));
					}

					// Remote call FreeLibrary
					for(int i=0; i<loadCount; ++i)
					{
						unloaded = System::UnloadDll((HMODULE)(*m_i)->modBaseAddr, (*p_iter)->th32ProcessID);
						
						// If even only one call will fail - I have to return 
						if(!unloaded) 
							break;
					}

					// Another way to do the same things.
					// Change .LoadCount value in LDR_MODULE structure of the remote process

					// ....
					// ....
				}
			}

			System::Close(m);
		}
	}

	System::Close(sysprss);
	return unloaded;
}


// Removes object from disk and memory
bool Cleaner::RemoveFile(QString filepath)
{

	// use client0::RemoveFile
	return DeleteFileA(filepath.toAscii().constData());

// 	if(removed)
// 	{
// 		WorkLog::GetLog().printmain(QString("object was successfully removed: ") + filepath);
// 	} else 
// 	{
// 		WorkLog::GetLog().printmain(QString("warning! Object was not removed: ") + filepath);
// 	}

}

bool Cleaner::IatReset(const PIAT_HOOK obj)
{
	BOOL written;

	if(!obj)
		return FALSE;

	written = System::WriteMemory(obj->pid, obj->piat, (LPVOID)&obj->originalApiAddr, sizeof(PVOID));

	if(!written)
	{
		// 
	}

	return written;
}

bool Cleaner::RemoveAllHooks(const DetectedItem *pItem)
{
	BOOL all_deleted = TRUE;

	for(int i=0; pItem && i<pItem->childCount(); i++)
	{
		// Enumerate all child items and reset hooks
		DetectedItem* hookItem = (DetectedItem*)pItem->child(i);

		// I don't know when it can occur, but who knows..
		// It's my habit to use compare with null
		if(!hookItem) continue;

		switch(hookItem->GetType())
		{
		case WIN_API_IMPORT_HOOK:
			if(IatReset((PIAT_HOOK)hookItem->GetDescrData()))
			{
				// Change color if hook was deleted
				hookItem->SetGreen();
				hookItem->setIcon(0, UiResources::GetMe().icoOk());
			} else {
				all_deleted = false;
				break;
			}

			break;

		//default:
		}
	}

	return all_deleted;
}

bool Cleaner::CleanAll(const QTreeWidget* tree)
{
	MessageBoxA(0, "cleanall", 0, 0);
	for(int i=0; i<tree->topLevelItemCount(); i++)
	{
		if(!RemoveAllHooks((DetectedItem *)tree->topLevelItem(i)))
		{
			break;
		}
	}

	return false;
}