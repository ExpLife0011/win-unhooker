
//	(c) Burlutsky Stanislav
//	Author: burluckij@gmail.com


#ifndef SETTINGS_H
#define SETTINGS_H

#include "RefObject.h"
#include "ui_objects.h"
#include "system.h"
#include <qtextcodec.h>
#include <qobject.h>
#include <QTime>
#include <QList>
#include <QHash>
#include <QScopedPointer>

// directory with configuration files
#define SETTINGS_DIR	"settings_x"

#define CONF_FILES_NUMBER	4

#define CONF_SYSLIBS		"syslibs.conf"
#define CONF_SYSLIBS_N		0

// Default size of file with protected libs
#define CONF_PROTLIBS_SIZE	1024*8

#define CONF_TRUSTED_SIZE	1024*8

#define CONF_SETTINGS		"settings.conf"
#define CONF_SETTINGS_N		1

#define CONF_TRUSTAPP		"trusted.conf"
#define CONF_TRUSTAPP_N		2

#define CONF_WHITELIST		"white.conf"
#define CONF_WHITELIST_N	3

#pragma pack(1)

// Head of trusted.conf file
typedef struct TRUSTED_HEAD
{
	ulong version;
	ulong length;
	ulong reserved;
	// ...
}TRUSTED_CONFIG_HEAD, *PTRUSTED_CONFIG_HEAD;

// Description of a trusted application
typedef struct TRUSTED_APP_
{
	ulong version; // version of TRSUTED_APP structure
	ulong fileSize; // size of trusted application file on disk
	ulong fileHash; // checksum
	char filePath[512]; // full path to the file
	// ...

}TRUSTED_APP, *PTRUSTED_APP;


typedef struct PROTECTED_LIB{
	char szlib[256];
	// .. 
}PROTECTED_LIB, *PPROTECTED_LIB;


// Main program settings file definition
typedef struct SETTINGS_DATA_
{
	ulong version;
	ulong language;
	uchar key[32];
	bool usefilelimits;
	bool enable_quarantine;
	bool enable_heauristic;
	bool enable_iat_list;
	ulong max_file_size;

}SETTINGS_DATA, *PSETTINGS_DATA;

#pragma pack()

const static SETTINGS_DATA default_settings = {1, 1, "free", false, true, true, true, 1024*1024*2};

// Information about a mapped file: handle of file, mapping and virtual base address in the memory
class MappedMemFile
{
	HANDLE m_hfile;
	HANDLE m_hmap;
	PVOID m_pMappedTo;
	DWORD m_size;
	QString m_filepath;

	mutable PCRITICAL_SECTION m_ptrCS;

// 	void to_copy(MappedMemFile& rhs)
// 	{
// 		this->m_hfile = rhs.m_hfile;
// 		rhs.m_hfile = INVALID_HANDLE_VALUE;
// 		this->m_hmap = rhs.m_hmap;
// 		rhs.m_hmap = NULL;
// 		this->m_pMappedTo = rhs.m_pMappedTo;
// 		rhs.m_pMappedTo = NULL;
// 	}

	void Close()
	{
		if(m_pMappedTo)
		{
			FlushViewOfFile(m_pMappedTo, 0);

			if(UnmapViewOfFile(m_pMappedTo))
				m_pMappedTo = NULL;
		}

		if (m_hmap)
			if(CloseHandle(m_hmap))
				m_hmap = NULL;

		if(m_hfile!=INVALID_HANDLE_VALUE)
			if(CloseHandle(m_hfile))
				m_hfile = INVALID_HANDLE_VALUE;

		DeleteCriticalSection(m_ptrCS);
		Memory::freemem(m_ptrCS);
	}

public:

	MappedMemFile(QString filePath = QString("nofile"), HANDLE hFile = INVALID_HANDLE_VALUE,
		HANDLE hMap = NULL, PVOID pMappedTo = NULL, DWORD size = 0
		): m_filepath(filePath), m_hfile(hFile), m_hmap(hMap), m_pMappedTo(pMappedTo), m_size(size)
	{
		m_ptrCS = (PCRITICAL_SECTION)Memory::getmem(sizeof(CRITICAL_SECTION));
		InitializeCriticalSection(m_ptrCS);
	}

// 	MappedMemHandles(const MappedMemHandles& rhs)
// 	{
// 		to_copy(const_cast<MappedMemHandles&>(rhs));
// 	}
// 					
// 	MappedMemHandles& operator=(const MappedMemHandles& rhs)
// 	{
// 		to_copy(const_cast<MappedMemHandles&>(rhs));
// 		return *this;
// 	}

	// Opens the file, loads in memory and returns object which describe memory region and has some handles
	static MappedMemFile* CreateFileMap(const QString& filepath, DWORD size);

	// Increases size of file mapping
	bool IncreaseFileSize(DWORD requiredSize);

	void Lock() const
	{
		EnterCriticalSection(m_ptrCS);
	}

	void Unlock() const
	{
		LeaveCriticalSection(m_ptrCS);
	}

	// Size of mapped region (in bytes)
	DWORD Size() const {
		return m_size;
	}

	QString FilePath() const {
		return m_filepath;
	}

	HANDLE FileHandle() const {
		return m_hfile;
	}

	HANDLE MapHandle() const {
		return m_hmap;
	}

	PVOID MappedAddr() const {
		return m_pMappedTo;
	}

	// Returns true if file is loaded in memory otherwise false
	BOOL State() const
	{
		return m_pMappedTo && m_hmap && (m_hfile!=INVALID_HANDLE_VALUE);
	}

	~MappedMemFile()
	{
		Close();
	}
};

typedef QHash< QString, QSharedPointer<MappedMemFile> >	HashMappedFiles;

class Settings: public QObject {

	Q_OBJECT

private:
	bool m_state;

	// These functions return full path to file on disk
	QString getProtectedConfigPath() const;
	QString getSettingsPath() const;
	QString getTrustedConfigPath() const;
	QString get_whitelist_path() const;

	// Array of strings which points to the files on disk
	QString m_ConfFiles[CONF_FILES_NUMBER];

	// Descriptors of mapped on memory files
	// Key - filePath (the same MappedMemFile::FilePath)
	HashMappedFiles	m_DescrMapFiles;

	// Returns descriptors of the mapped file by his full name (filePath)
	MappedMemFile* getMapDescr(QString filePath) const;

	// Opens early created file or create a new empty file, with the following rights - read, write
	//HANDLE create_or_open(const QString& filepath) const;

	// Returns an object by filepath which describes mapping
	const MappedMemFile* getMapInfo(const QString& filepath) const;

	// Gets size of mapping in memory (in bytes)
	DWORD getMapSize(const QString& filepath) const;

	// Returns pointer to the base address of mapping
	PVOID getMapAddr(const QString& filepath) const;

	// Loads list of protected IAT libs
	bool loadConfigProtectedLibs();

	// Loads  main program settings (key, language, etc..)
	bool loadConfigSettings();

	// Loads info about trusted applications
	bool loadConfigTrustedApps();

	//bool Load_Whitelist();

public:

	Settings();

	bool Load();

	// Returns state of initializing process
	bool State() const;

	// Emits signals with information about protected IAT libs
	void EmitProtectedLibraries();

	// Adds new library to the protected libraries list
	bool AddProtectedLibrary(QString libName);

	// Removes a library from protected libraries list
	bool RemoveProtectedLibrary(QString libName);

	// Fires when ..
	bool CleanOutProtectedLibs();

	// 
	void EmitTrustedApps();

	// Adds new trusted application to the config file
	bool AddTrustedApp(QString appPath);

	// Seeks exists entry in trusted applications list's
	PTRUSTED_APP LookupTrustedApp(QString appPath);

	// Removes a trusted application from application's lists
	bool RemoveTrustedApp(QString appPath);

	// ..
	bool CleanOutTrustedApps();
	
	// these functions enable or disable some options
	bool EnableQuarantine(bool);
	bool EnableProtectingIATList(bool);
	bool EnableFileLimits(bool);
	bool EnableHeuristic(bool);

	// these functions return configuration info right from .conf file
	bool UseQuarantine() const;
	bool UseHeuristic() const;
	bool UseFileLimits() const;
	bool UseProtectingIATList() const;

	~Settings();

signals:

	// Fires when program is loading (during reading info from .conf files)
	void ProtectedLibLoaded(QString libName);

	// Fires when protected library was removed
	void ProtectedLibRemoved(QString libName);

	// Fires when the program removes some entries in the file
	void ProtectedLibWasMoved(QString appPath, PPROTECTED_LIB pOldPosition, PPROTECTED_LIB pNewPosition);

	// Fires when program loads or adds description of new trusted application
	void TrustedAppLoaded(QString appPath, PTRUSTED_APP pDescription);

	// Fires when trusted application was removed
	void TrustedAppRemoved(QString appPath);

	// Fires when the program removes some entries in the file
	void TrustedAppWasMoved(QString appPath, PTRUSTED_APP pOldPosition, PTRUSTED_APP pNewPosition);
};

#endif
