
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014


#ifndef QUARANTINE_H
#define QUARANTINE_H

#include "RefObject.h"
#include "CBase.h"
#include "QLinkedList.h"
#include <string.h>
#include <qobject.h>
#include <QTime>

#define DEFAULT_QUARANTINE_DIR_NAME	"killed"
#define KILLED_EXTENSION			".killed"


typedef struct quarantine_file_ {
	char found_place[MAX_PATH]; // place where the file was found
	char killedName[MAX_PATH]; // the file name in the quarantine directory
	char txtTime[100]; // time when when the file was added
	unsigned long file_size; // size of the file
	unsigned long type; // rootkit's type
	// ... body of the file ...
} QUARANTINE_FILE, *PQUARANTINE_FILE;

typedef QLinkedList<PQUARANTINE_FILE> KilledFiles, *PKilledFiles;

class Quarantine: public QObject, protected CBase
{
	Q_OBJECT

private:
	QString m_dir; // quarantine directory
	bool m_state;
	KilledFiles m_killedList;
	
	HANDLE getFileReadHandle(__in const QString& fileName) const;
	bool readInfo(__in const QString& fileName, __out PQUARANTINE_FILE pqfInfo);
	ulong buildKilledFile(__in const QString& dest, __in HANDLE hsrc, __in const PQUARANTINE_FILE pqfInfo);

	Quarantine(const Quarantine&);
	Quarantine& operator=(const Quarantine&);

public:
	Quarantine(QString dir = DEFAULT_QUARANTINE_DIR_NAME);
	bool Load();

	// Sends copy of 'fileName' object to the local storage
	bool AddObject(__in const QString& fileName, __out QString* outKilledFilePath = NULL);

	// Deletes object from quarantine
	// killedName - file name in quarantine with extension '.killed'
	bool DeleteObject(__in const QString& killedName /* only file name */);

	// Recoveries the file without deleting from storage
	bool Backup(__in const QString& killedName, __in QString oldPlace = QString());

	const QString Dir() const {
		return m_dir;
	}

	bool GetStatus() const {
		return m_state;
	}

	~Quarantine();

signals:
	void signalObjectsLoaded(const KilledFiles* pkf); // signal emits when all objects were loaded
	//void objectWasRemoved(); // signal emits when object was removed from quarantine
	void signalNewObject(const QUARANTINE_FILE* pFileInfo); // emits when we want to add new object
};


#endif