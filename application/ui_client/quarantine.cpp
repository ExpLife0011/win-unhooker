
//	(c) Burlutsky Stanislav
//	Author: BURLUCKIJ@GMAIL.COM

#include "quarantine.h"
#include "system.h"
#include "worklog.h"
#include <functional>

using namespace Memory;
using namespace std;

// Creates directory only if it wasn't created early
Quarantine::Quarantine(QString dir):m_state(false)
{
	QString sdir;

	if(dir == DEFAULT_QUARANTINE_DIR_NAME)
	{
		char currdir[MAX_PATH];

		if(!GetCurrentDirectoryA(sizeof(currdir)/sizeof(char), currdir))
		{
			WorkLog::GetLog().printmain("error: could not get the current directory");
			return;
		}

		sdir = QString(currdir) + QString("\\") + QString(dir);
	} else 
	{
		// In this case user must pass full path to the directory
		sdir = QString(dir);
	}

	if(!CreateDirectoryA(sdir.toAscii().constData(), NULL))
	{
		if(GetLastError() != ERROR_ALREADY_EXISTS)
		{
			WorkLog::GetLog().printmain(QString("error: could not create quarantine directory: %1").arg(sdir));
		}
	}

	WorkLog::GetLog().printmain(QString("Quarantine path: %1").arg(sdir));

	this->m_dir = sdir;
	m_state = true;
}

bool Quarantine::Load()
{
	WIN32_FIND_DATAA w32files;
	QString strDir(m_dir + QString("\\*"));

	HANDLE hFile = FindFirstFileA(strDir.toAscii().constData(), &w32files);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do {
			//MessageBoxA(0, w32files.cFileName, "loadFiles", 0);

			if(!(w32files.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				PQUARANTINE_FILE pqf_info = (PQUARANTINE_FILE)getmem(sizeof(QUARANTINE_FILE));
				if (pqf_info)
				{
					//tmp.clear();
					QString tmpFilePath = m_dir + QString("\\") + QString(w32files.cFileName);

					if(readInfo(tmpFilePath, pqf_info))
					{
						WorkLog::GetLog().printmain(QString("Description of the file (%1) from quarantine was loaded successfully")
							.arg(tmpFilePath));

						m_killedList.push_back(pqf_info);
						emit signalNewObject(pqf_info);
					} else 
					{
						WorkLog::GetLog().printmain(QString("error: couldn't read info about %1 in quarantine").arg(tmpFilePath));
					}
				}
			}

		} while (FindNextFileA(hFile, &w32files));

		emit signalObjectsLoaded(&m_killedList);
		FindClose(hFile);
	}

	return true;
}

// with basic validation
bool Quarantine::readInfo(__in const QString& fileName, __out PQUARANTINE_FILE pqfInfo)
{
	bool result = false;
	DWORD dwReaded = 0;
	HANDLE hfile = CreateFileA(fileName.toAscii().constData(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	
	if(hfile != INVALID_HANDLE_VALUE)
	{
		result = ReadFile(hfile, pqfInfo, sizeof(QUARANTINE_FILE), &dwReaded, NULL);
		CloseHandle(hfile);
	}

	if(result)
		result = kstrstr(pqfInfo->killedName, KILLED_EXTENSION);

	return result;
}

// get handle to a file with read_only rights
HANDLE Quarantine::getFileReadHandle(const QString& fileName) const
{
	return CreateFileA(fileName.toAscii().constData(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
}

// Removes a file from quarantine
bool Quarantine::DeleteObject(const QString& killedName)
{
 	for(KilledFiles::iterator i = m_killedList.begin(); i!=m_killedList.end(); ++i)
	{
 		if(kstrcmp((*i)->killedName, killedName.toAscii().constData())==0)
		{
			QString fullFileAddr = m_dir + QString("\\") + QString(killedName);
			 if(DeleteFileA(fullFileAddr.toAscii().constData()))
				 return m_killedList.removeOne(*i);
		}
	}

	return false;
}

// Recoveries file to the old place (where file was found) without removing from storage
bool Quarantine::Backup(const QString& killedName, QString oldPlace)
{
	bool recovered = false;
	QString fullFileAddrInStorage;
	HANDLE hOldPlace = INVALID_HANDLE_VALUE;

	for(KilledFiles::iterator i = m_killedList.begin(); i!=m_killedList.end() && !recovered; ++i)
	{
		if(kstrcmp((*i)->killedName, killedName.toAscii().constData())==0)
		{
			fullFileAddrInStorage = m_dir + QString("\\") + QString(killedName);

			// .. HAVE TO unload file if it was loaded early
// 			if(System::UnloadObject((*i)->found_place)){
// 				MessageBoxA(0, "Unloaded successful", "backup:UnloadObject", 0);
// 			}

			if(!oldPlace.length())
				oldPlace = QString((*i)->found_place);

			hOldPlace = CreateFileA(oldPlace.toAscii().constData(), GENERIC_ALL,
				FILE_SHARE_WRITE|FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
			HANDLE hReadKilledFile = getFileReadHandle(fullFileAddrInStorage);
			
			if(hOldPlace == INVALID_HANDLE_VALUE)
			{
				WorkLog::GetLog().printmain(QString("error: couldn't open %1").arg(oldPlace));
				break;
			}

			if(hReadKilledFile != INVALID_HANDLE_VALUE)
			{
				DWORD moved_fp = SetFilePointer(hReadKilledFile, sizeof(QUARANTINE_FILE), NULL, FILE_BEGIN);

				if(moved_fp != INVALID_SET_FILE_POINTER)
				{
					const ulong length = 1024*4;
					uchar buffer[length];
					DWORD dwRead, dwWritten, wr;
					bool file_io = true;

					for(dwWritten = 0; (dwWritten < (*i)->file_size) && file_io; dwWritten += dwRead)
						if(file_io = ReadFile(hReadKilledFile, buffer, length, &dwRead, 0))
							file_io = WriteFile(hOldPlace, buffer, dwRead, &wr, 0);

					recovered = dwWritten == (*i)->file_size;
				}

				CloseHandle(hReadKilledFile);
			} else
			{
				WorkLog::GetLog().printmain(QString("error: couldn't open %1").arg(fullFileAddrInStorage));
			}
		}
	}

	if(hOldPlace != INVALID_HANDLE_VALUE)
		CloseHandle(hOldPlace);

	if(recovered)
	{
		WorkLog::GetLog().printmain(QString("error: %1 wasn't recovered").arg(oldPlace));
	}
	else 
	{
		WorkLog::GetLog().printmain(QString("%1 was recovered successfully").arg(oldPlace));
	}

	return recovered;
}

bool Quarantine::AddObject(__in const QString& fileName, __out QString* outKilledFilePath)
{
	bool everything_ok = false;
	DWORD filesize = 0;
	HANDLE hfile = INVALID_HANDLE_VALUE;
	std::hash<const char*> ptr_hash;

	hfile = getFileReadHandle(fileName);

	if(hfile != INVALID_HANDLE_VALUE)
	{
		if(filesize = GetFileSize(hfile, NULL))
		{
			PQUARANTINE_FILE pfileInfo = (PQUARANTINE_FILE)getmem(sizeof(QUARANTINE_FILE));
			if(pfileInfo)
			{
				kmemset(pfileInfo, 0, sizeof(QUARANTINE_FILE));
				pfileInfo->type = 0;
				pfileInfo->file_size = filesize;

				kstrcpy(pfileInfo->found_place, fileName.toAscii().constData());
				wsprintfA(pfileInfo->killedName, "%x_%x.killed", rand()*1000, ptr_hash(fileName.toAscii().constData()));
				kstrcpy(pfileInfo->txtTime, QDateTime::currentDateTime().toString(Qt::TextDate).toAscii().constData());

				QString killedFilePath(QString(m_dir) + QString("\\") + QString(pfileInfo->killedName));

				everything_ok = buildKilledFile(killedFilePath.toAscii().constData(), hfile, pfileInfo);

				if(everything_ok)
				{
					if(outKilledFilePath){
						*outKilledFilePath = killedFilePath;
					}

					WorkLog::GetLog().printmain(QString("%1 was saved in quarantine").arg(fileName));

					m_killedList.push_back(pfileInfo);
					emit signalNewObject(pfileInfo);
				}

				CloseHandle(hfile);
			} else 
			{
				WorkLog::GetLog().printmain(QString("error: couldn't allocate memory for new object: %1").arg(fileName));
			}
		} else 
		{
			WorkLog::GetLog().printmain(QString("error: couldn't get file size: %1").arg(fileName));
		}
	} else 
	{
		WorkLog::GetLog().printmain(QString("error: call getFileReadHandle(%1) failed").arg(fileName));
	}
	
	return everything_ok;
}

ulong Quarantine::buildKilledFile(__in const QString& dest, __in HANDLE hsrc, __in const PQUARANTINE_FILE pqfInfo)
{
	ulong st = 0;
	char buffer[1024*4];
	DWORD dwWritten, dwRead=1;

	HANDLE hnewKilled = CreateFileA(dest.toAscii().constData(), GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if(hnewKilled != INVALID_HANDLE_VALUE)
	{
		// write header with quarantine_file structure
		WriteFile(hnewKilled, pqfInfo, sizeof(QUARANTINE_FILE), &dwWritten, NULL);
		st += dwWritten;

		// writes body (I don't know may be its wrong method, I don't use file pointers)
		while(dwRead)
		{
			if(ReadFile(hsrc, buffer, sizeof(buffer), &dwRead, NULL))
			{
				if(dwRead)
				{
					//SetEndOfFile(hnewKilled);

					WriteFile(hnewKilled, buffer, dwRead, &dwWritten, NULL);
					st += dwWritten;
				}
			}

			//SetFilePointer(hsrc, dwRead, NULL, FILE_CURRENT);
		}

		CloseHandle(hnewKilled);
	} else 
	{
		WorkLog::GetLog().printmain(QString("error: couldn't open file: %1").arg(dest));
	}

	return st;
}


Quarantine::~Quarantine()
{
	for(KilledFiles::iterator i = m_killedList.begin(); i!=m_killedList.end(); ++i)
	{
		freemem(*i);
	}
}