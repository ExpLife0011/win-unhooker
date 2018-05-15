
//	(c) Burlutsky Stanislav
//	Author: burluckij@gmail.com


#include "Window.h"
#include "settings.h"

using namespace Memory;


// Creates directory if it wasn't created early and initialize strings
Settings::Settings()
{
	char currdir[MAX_PATH];

	if(!GetCurrentDirectoryA(sizeof(currdir)/sizeof(char), currdir))
	{
		m_state = false;
		return;
	}

	QString sdir = QString(currdir) + QString("\\") + QString(SETTINGS_DIR);

	if(!CreateDirectoryA(sdir.toAscii().constData(), NULL))
	{
		if(GetLastError() != ERROR_ALREADY_EXISTS)
		{
			m_state = false;
			return;
		}
	}

	m_ConfFiles[CONF_SYSLIBS_N] = sdir + QString("\\") + QString(CONF_SYSLIBS);
	m_ConfFiles[CONF_SETTINGS_N] = sdir + QString("\\") + QString(CONF_SETTINGS);
	m_ConfFiles[CONF_TRUSTAPP_N] = sdir + QString("\\") + QString(CONF_TRUSTAPP);
	m_ConfFiles[CONF_WHITELIST_N] = sdir + QString("\\") + QString(CONF_WHITELIST);
}

bool Settings::State() const
{
	return m_state;
}

QString Settings::getProtectedConfigPath() const
{
	return m_ConfFiles[CONF_SYSLIBS_N];
}

QString Settings::getSettingsPath() const
{
	return m_ConfFiles[CONF_SETTINGS_N];
}

QString Settings::getTrustedConfigPath() const
{
	return m_ConfFiles[CONF_TRUSTAPP_N];
}

QString Settings::get_whitelist_path() const
{
	return m_ConfFiles[CONF_WHITELIST_N];
}

MappedMemFile* Settings::getMapDescr(QString filePath) const
{
	HashMappedFiles::const_iterator i = m_DescrMapFiles.find(filePath);
	if (i != m_DescrMapFiles.end() && !i->isNull() && (i->data()->FilePath() == filePath)){
		return i->data();
	}

	return NULL;
}

const MappedMemFile* Settings::getMapInfo(const QString& filepath) const
{
	return getMapDescr(filepath);
}

DWORD Settings::getMapSize(const QString& filepath) const
{
	DWORD size = 0;
	const MappedMemFile* mmf = getMapInfo(filepath);
	
	if(mmf && mmf->State())
	{
		size = mmf->Size();
	}

	return size;
}

PVOID Settings::getMapAddr(const QString& filepath) const
{
	PVOID p = NULL;
	const MappedMemFile* mmf = getMapInfo(filepath);

	if(mmf && mmf->State())
	{
		p = mmf->MappedAddr();
	}

	return p;
}

//! I have to save previous state
bool MappedMemFile::IncreaseFileSize(DWORD requiredSize)
{
	//MappedMemFile old = *this;

	// Close old session
	this->Close();

	// теряется ссылка на описатель критической секции

	MappedMemFile* pMappedFile = CreateFileMap(this->FilePath(), requiredSize);

	if(pMappedFile)
	{
		*this = *pMappedFile;
		return State();
	} else
		return false;
}

MappedMemFile* MappedMemFile::CreateFileMap(const QString& filepath, DWORD requiredSize)
{
	HANDLE hmap = NULL;
	PVOID pMappedTo = NULL;
	DWORD currentFileSize = 0;
	MappedMemFile* pMappedFile = NULL;

	HANDLE hfile = System::CreateOrOpen(filepath);

	if(hfile != INVALID_HANDLE_VALUE)
	{
		currentFileSize = GetFileSize(hfile, 0);

		// If file on disk is bigger than required - change required size on the real file size
		if(currentFileSize > requiredSize){
			requiredSize = currentFileSize;
		}

		hmap = CreateFileMappingA(hfile, NULL, PAGE_READWRITE, 0, requiredSize, NULL);

		if (hmap)
		{
			pMappedTo = MapViewOfFile(hmap, FILE_MAP_READ|FILE_MAP_WRITE, 0, 0, 0);

			if (pMappedTo)
			{
				pMappedFile = new (std::nothrow) MappedMemFile(filepath, hfile, hmap, pMappedTo, requiredSize);
			}
			else
			{
				WorkLog::GetLog().printmain(QString("error: couldn't load the file in memory %1").arg(filepath));
			}
		} 
		else 
		{
			WorkLog::GetLog().printmain(QString("error: couldn't create the file mapping %1").arg(filepath));
		}

		WorkLog::GetLog().printmain(QString("file was successfully loaded %1").arg(filepath));
	}
	else
	{
		WorkLog::GetLog().printmain(QString("error: couldn't open the file %1").arg(filepath));
	}

	return pMappedFile;
}

// Sends information about protected libs
void Settings::EmitProtectedLibraries()
{
	const MappedMemFile* protectedLibs = getMapInfo(getProtectedConfigPath());

	//protectedLibs->Lock();

	ulong length = *((ulong*)protectedLibs->MappedAddr());
	PPROTECTED_LIB pLibsArray = (PPROTECTED_LIB)((char*)protectedLibs->MappedAddr() + sizeof(ulong));

	for(ulong i = 0; i < length; i++, pLibsArray++)
	{
		emit ProtectedLibLoaded(QString(pLibsArray->szlib));
	}

	//protectedLibs->Unlock();
}

void Settings::EmitTrustedApps()
{
	const MappedMemFile* pTrustedConfig = getMapInfo(getTrustedConfigPath());

	pTrustedConfig->Lock();

	PTRUSTED_CONFIG_HEAD phdrConfig = (PTRUSTED_CONFIG_HEAD)pTrustedConfig->MappedAddr();
	PTRUSTED_APP pApp = (PTRUSTED_APP)((char*)pTrustedConfig->MappedAddr() + sizeof(TRUSTED_CONFIG_HEAD));

	for(ulong i_App = 0; i_App < phdrConfig->length; i_App++, pApp++)
	{
		emit TrustedAppLoaded(QString(pApp->filePath), pApp);
	}

	pTrustedConfig->Unlock();
}

// work with unknown data format
bool Settings::loadConfigSettings()
{
	BOOL loaded = FALSE;
	MappedMemFile* pMappedFile = MappedMemFile::CreateFileMap(getSettingsPath(), sizeof(SETTINGS_DATA));

	if(pMappedFile && (loaded = pMappedFile->State()))
	{
		PSETTINGS_DATA psettings = (PSETTINGS_DATA)pMappedFile->MappedAddr();

		// load default configuration
		if(psettings->version == 0)
		{
			memcpy(psettings, &(::default_settings), sizeof(default_settings));
			WorkLog::GetLog().printmain("settings file wasn't found, the program will use default configuration");
		}

		m_DescrMapFiles.insert(pMappedFile->FilePath(), HashMappedFiles::mapped_type(pMappedFile));
		// push new value!!
	}

	return loaded;
}

bool Settings::loadConfigTrustedApps()
{
	bool loaded = false;
	MappedMemFile* pMappedFile = MappedMemFile::CreateFileMap(getTrustedConfigPath(), CONF_TRUSTED_SIZE);

	if(pMappedFile && (loaded = pMappedFile->State()))
	{
		m_DescrMapFiles.insert(pMappedFile->FilePath(), HashMappedFiles::mapped_type(pMappedFile));
	}

	return loaded;
}

bool Settings::loadConfigProtectedLibs()
{
	BOOL loaded = FALSE;
	MappedMemFile* pMappedFile = MappedMemFile::CreateFileMap(getProtectedConfigPath(), CONF_PROTLIBS_SIZE);

	if(pMappedFile && (loaded = pMappedFile->State()))
	{
		m_DescrMapFiles.insert(pMappedFile->FilePath(), HashMappedFiles::mapped_type(pMappedFile));
	}

	return loaded;
}

bool Settings::Load()
{
	if (!loadConfigSettings())
	{
		WorkLog::GetLog().printmain(QString("error: %1 was not loaded").arg(getSettingsPath()));
		return false;
	}

	if(!loadConfigProtectedLibs())
	{
		WorkLog::GetLog().printmain(QString("error: %1 was not loaded").arg(getProtectedConfigPath()));
		return false;
	}

	if(!loadConfigTrustedApps())
	{
		WorkLog::GetLog().printmain(QString("error: %1 was not loaded").arg(getTrustedConfigPath()));
		return false;
	}

	return true;
}

PTRUSTED_APP Settings::LookupTrustedApp(QString appPath)
{
	PTRUSTED_APP foundEntry = NULL;
	PTRUSTED_CONFIG_HEAD phdrConfig = NULL;
	PTRUSTED_APP pApp = NULL;
	const MappedMemFile* pConfig = getMapInfo(getTrustedConfigPath());

	if(!pConfig && !pConfig->State())
		return false;

	pConfig->Lock();

	appPath = appPath.toLower();
	phdrConfig = (PTRUSTED_CONFIG_HEAD)pConfig->MappedAddr();
	pApp = (PTRUSTED_APP)((BYTE*)pConfig->MappedAddr() + sizeof(TRUSTED_CONFIG_HEAD));

	for(ulong i_App = 0; i_App < phdrConfig->length; i_App++, pApp++)
	{
		if(QString(pApp->filePath).toLower() == appPath)
		{
			foundEntry = pApp;
			break;
		}
	}

	pConfig->Unlock();
	return foundEntry;
}

// !!! modify!!! 
// All new descriptions are added at the end of the file
bool Settings::AddTrustedApp(QString filePath)
{
	bool added = false;
	PTRUSTED_CONFIG_HEAD phdrConfig = NULL;
	MappedMemFile* pMappedFile = const_cast<MappedMemFile*>(getMapInfo(getTrustedConfigPath()));

	if(!pMappedFile && !pMappedFile->State())
		return false;

// 	if(!State())
// 		return false;

	if (this->LookupTrustedApp(filePath)){
		return false;
	}

	pMappedFile->Lock();
	phdrConfig = (PTRUSTED_CONFIG_HEAD)pMappedFile->MappedAddr();

	// If file doesn't have free space - increase file size
	// DONT UNDERSTAND THIS!
	if((pMappedFile->Size() - sizeof(TRUSTED_CONFIG_HEAD))/sizeof(TRUSTED_APP) < phdrConfig->length + 1)
	{
		WorkLog::GetLog().printmain(QString("Increasing %1 size from %2 to %3")
			.arg(pMappedFile->FilePath())
			.arg(pMappedFile->Size())
			.arg(pMappedFile->Size() * 2));

		if (!pMappedFile->IncreaseFileSize(pMappedFile->Size() * 2))
		{
			WorkLog::GetLog().printmain("error: file size has not increased");
			pMappedFile->Unlock();
			return false;
		}
	}

	PTRUSTED_APP pTrustedApp = (PTRUSTED_APP)((char*)pMappedFile->MappedAddr() + sizeof(TRUSTED_CONFIG_HEAD));
	PTRUSTED_APP appInfo = pTrustedApp + phdrConfig->length;

	// Create and fill structure with info about application
	strcpy(appInfo->filePath, filePath.toAscii().constData());
	// ...

	phdrConfig->length++;
	added = FlushViewOfFile(pMappedFile->MappedAddr(), phdrConfig->length*sizeof(TRUSTED_APP) + sizeof(TRUSTED_CONFIG_HEAD));
	pMappedFile->Unlock();

	WorkLog::GetLog().printmain(QString("%1 was added to trusted applications list: %2").arg(filePath).arg(added));

	if(added)
		emit TrustedAppLoaded(QString(appInfo->filePath), NULL);

	return added;
}

bool Settings::RemoveTrustedApp(QString filePath)
{
	bool removed = false;
	PTRUSTED_CONFIG_HEAD phdrConfig = NULL;
	PTRUSTED_APP poldPosition = NULL, pchangedPosition = NULL, pApp = NULL, pFirstApp = NULL;
	const MappedMemFile* pConfig = getMapInfo(getTrustedConfigPath());

	if(!pConfig && !pConfig->State())
		return false;

// 	if(!State())
// 		return false;

	pConfig->Lock();

	filePath = filePath.toLower();
	phdrConfig = (PTRUSTED_CONFIG_HEAD)pConfig->MappedAddr();
	pApp = (PTRUSTED_APP)((BYTE*)pConfig->MappedAddr() + sizeof(TRUSTED_CONFIG_HEAD));
	pFirstApp = pApp;

	for(ulong i_App = 0; i_App < phdrConfig->length; i_App++, pApp++)
	{
		if(QString(pApp->filePath).toLower() == filePath)
		{
			// If file contains only one description - leave it, just decrement counter
			if(i_App != phdrConfig->length - 1)
			{
				// 1. Copies the last element at the current position
				poldPosition = &pFirstApp[phdrConfig->length - 1];
				pchangedPosition = pApp;
				*pchangedPosition = *poldPosition;
				//pFirstApp[i_App] = pFirstApp[phdrConfig->length - 1];
			}

			// 2. Decrements counter in the .config file
			phdrConfig->length--;
			removed = FlushViewOfFile(pConfig->MappedAddr(), phdrConfig->length*sizeof(TRUSTED_APP) + sizeof(TRUSTED_CONFIG_HEAD));
			break;
		}
	}

	pConfig->Unlock();

	WorkLog::GetLog().printmain(QString("%1 was removed from trusted applications list: %2").arg(filePath).arg(removed));

	if(removed)
	{
		emit TrustedAppRemoved(filePath);

		// Don't emit the signal when it's last element 
		if(pchangedPosition)
			emit TrustedAppWasMoved(QString(pchangedPosition->filePath), poldPosition, pchangedPosition);
	}

	return removed;
}

bool Settings::CleanOutTrustedApps()
{
	bool cleaned = false;
	PTRUSTED_CONFIG_HEAD phdrConfig = 0;
	const MappedMemFile* pConfig = getMapInfo(getTrustedConfigPath());

	if(!pConfig && !pConfig->State()) return false;

	pConfig->Lock();

	phdrConfig = (PTRUSTED_CONFIG_HEAD)pConfig->MappedAddr();
	phdrConfig->length = 0;
	cleaned = FlushViewOfFile(pConfig->MappedAddr(), sizeof(TRUSTED_CONFIG_HEAD));
	pConfig->Unlock();

	return cleaned;
}

bool Settings::AddProtectedLibrary(QString libName)
{
	bool added = false;
	ulong countOfLibs = 0;
	MappedMemFile* pMappedFile = const_cast<MappedMemFile*>(getMapInfo(getProtectedConfigPath()));

	if(!pMappedFile)
		return false;

	pMappedFile->Lock();

	if(State())
	{
		countOfLibs = *((ulong*)pMappedFile->MappedAddr());

		// If file doesn't have free space - increase file size
		if((pMappedFile->Size() - sizeof(ulong))/sizeof(PROTECTED_LIB) < countOfLibs + 1)
		{
			WorkLog::GetLog().printmain(QString("Increasing %1 size from %2 to %3")
				.arg(pMappedFile->FilePath())
				.arg(pMappedFile->Size())
				.arg(pMappedFile->Size() * 2));

			if (!pMappedFile->IncreaseFileSize(pMappedFile->Size() * 2))
			{
				// Prints in log
				WorkLog::GetLog().printmain("error: file size has not increased");
				pMappedFile->Unlock();
				return false;
			}
		}

		ulong *pCountOfLibs = (ulong*)pMappedFile->MappedAddr();
		PPROTECTED_LIB pProtectedLibs = (PPROTECTED_LIB)((char*)pMappedFile->MappedAddr() + sizeof(ulong));
		PPROTECTED_LIB insert_pos = pProtectedLibs + (*pCountOfLibs);

		// Fills structure ..
		strcpy(insert_pos->szlib, libName.toAscii().constData());
		// ..

		(*pCountOfLibs)++;

		added = FlushViewOfFile(pMappedFile->MappedAddr(), (*pCountOfLibs) * sizeof(PROTECTED_LIB) + sizeof(ulong));
	}

	pMappedFile->Unlock();

	WorkLog::GetLog().printmain(QString("%1 was added to protected libraries list: %2").arg(libName).arg(added));

	if(added)
		emit ProtectedLibLoaded(libName);

	return added;
}

bool Settings::RemoveProtectedLibrary(QString libName)
{
	bool removed = false;
	PPROTECTED_LIB poldPosition = NULL, pchangedPosition = NULL;
	const MappedMemFile* pConfig = /*const_cast<MappedMemFile*>*/getMapInfo(getProtectedConfigPath());

	if(!pConfig && !pConfig->State())
		return false;

// 	if(!State())
// 		return false;

	pConfig->Lock();

	libName = libName.toLower();
	ulong* pLength = (ulong*)pConfig->MappedAddr();
	PPROTECTED_LIB pProtectedLib = (PPROTECTED_LIB)((char*)pConfig->MappedAddr() + sizeof(ulong));
	PPROTECTED_LIB pConfigsData = pProtectedLib;

	for(ulong i_ProtectedLib = 0; i_ProtectedLib < *pLength; i_ProtectedLib++, pProtectedLib++)
	{
		if(QString(pProtectedLib->szlib).toLower() == libName)
		{
			// Removing procedure:
			if(i_ProtectedLib != *pLength - 1)
			{
				// 1. Copies the last element at the current position
				poldPosition = &pConfigsData[*pLength - 1];
				pchangedPosition = pProtectedLib;
				*pchangedPosition = *poldPosition;

				//pConfigsData[i] = pConfigsData[*pLength-1];
			}

			// 2. Decrements of counter in the .config file
			(*pLength)--;
			removed = FlushViewOfFile(pConfig->MappedAddr(), (*pLength)*sizeof(PROTECTED_LIB) + sizeof(ulong));
			break;
		}
	}

	pConfig->Unlock();

	WorkLog::GetLog().printmain(QString("%1 was removed from protected libraries list: %2").arg(libName).arg(removed));

	if(removed)
	{
		emit ProtectedLibRemoved(libName);

		if(pchangedPosition)
			emit ProtectedLibWasMoved(QString(pchangedPosition->szlib), poldPosition, pchangedPosition);
	}

	return removed;
}

bool Settings::CleanOutProtectedLibs()
{
	bool cleaned = false;
	PPROTECTED_LIB pOldPos = NULL, pNewPos = NULL;
	const MappedMemFile* pConfig = /*const_cast<MappedMemFile*>*/getMapInfo(getProtectedConfigPath());

	if(!pConfig && !pConfig->State())
		return false;

	pConfig->Lock();

	ulong* pLength = (ulong*)pConfig->MappedAddr();
	*pLength = 0;
	cleaned = FlushViewOfFile(pConfig->MappedAddr(), sizeof(ulong));

	pConfig->Unlock();
	return cleaned;
}

bool Settings::EnableQuarantine(bool state)
{
	bool changed = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		WorkLog::GetLog().printmain(state?"using of quarantine is enabled":"using of quarantine is disabled");
		psettings->enable_quarantine = state;
		changed = FlushViewOfFile((PVOID)psettings, 0);
	}

	return changed;
}

bool Settings::EnableProtectingIATList(bool state)
{
	bool changed = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		WorkLog::GetLog().printmain(state?"protection of the system libraries is enabled":"protection of the system libraries is disabled");
		psettings->enable_iat_list = state;
		changed = FlushViewOfFile((PVOID)psettings, 0);
	}

	return changed;
}

bool Settings::EnableFileLimits(bool state)
{
	bool changed = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		WorkLog::GetLog().printmain(state?"file limits are enabled":"file limits are disabled");
		psettings->usefilelimits = state;
		changed = FlushViewOfFile((PVOID)psettings, 0);
	}

	return changed;
}

bool Settings::EnableHeuristic(bool state)
{
	bool changed = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		WorkLog::GetLog().printmain(state?"heuristic is enabled":"heuristic is disabled");
		psettings->enable_heauristic = state;
		changed = FlushViewOfFile((PVOID)psettings, 0);
	}

	return changed;
}

bool Settings::UseQuarantine() const
{
	bool state = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		state = psettings->enable_quarantine;
	}

	return state;
}

bool Settings::UseHeuristic() const
{
	bool state = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		state = psettings->enable_heauristic;
	}

	return state;
}

bool Settings::UseFileLimits() const
{
	bool state = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		state = psettings->usefilelimits;
	}

	return state;
}

bool Settings::UseProtectingIATList() const
{
	bool state = false;
	PSETTINGS_DATA psettings = (PSETTINGS_DATA)getMapAddr(getSettingsPath());

	if(psettings)
	{
		state = psettings->enable_iat_list;
	}

	return state;
}

Settings::~Settings()
{
	// All files will be unloaded automatically 
}
