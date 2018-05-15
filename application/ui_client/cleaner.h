
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#ifndef CLEANER_H
#define CLEANER_H

#include <QtCore>
#include "System.h"
#include "worklog.h"
#include "RefObject.h"
#include "ex_items.h"

//////////////////////////////////////////////////////////////////////////
/*
	1. If quarantine is enabled, before deleting a malware object will
	be saved in quarantine.

	2. Object will be saved in quarantine only if it can be deleted correctly
	(remove: hooks, files, keys etc..)

	3. Nesting level in UI tree - 2. First level it's main description of
	suspicious object- in this case file on disk. The second level are sets
	of characteristics suspicious activity(hooks, key, connections and etc..).
*/

class Cleaner: protected CBase {
private:
	System m_sys;

public:

	// Unloads early loaded object(process, module) from the system memory
	// for processes - terminate call
	// for modules - remote call UnloadLibrary
	BOOL UnloadObject(__in const char* szFilePath);

	// Delete interceptor in IMPORT APPLICATION TABLE
	bool IatReset(const PIAT_HOOK obj);

	// Deletes all hooks and returns true if only all hooks were deleted
	bool RemoveAllHooks(const DetectedItem *pItem);

	bool CleanAll(const QTreeWidget* tree);

	// Removes file from disk. Before removing deletes all hooks.
	bool RemoveFile(QString filepath);

	Cleaner()
	{
		
	}

	~Cleaner()
	{

	}
};

#endif // CLEANER_H
