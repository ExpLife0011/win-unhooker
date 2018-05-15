
//	(c) Burlutsky Stanislav
//	Author: BURLUCKIJ@GMAIL.COM

#ifndef WORKLOG_H
#define WORKLOG_H

#include <qstring.h>
#include "system.h"

#define DEFAULT_WORKLOG_DIR_NAME	"worklog"
#define LOG_FILES_NUMBER			2

#define MAIN_LOG_INDEX				0
#define MAIN_LOG					"worklog"
#define SCAN_LOG_INDEX				1
#define SCAN_LOG					"scanlog"

//////////////////////////////////////////////////////////////////////////
// main_nxxxxxxxx - main work log, have the most important info
// scanlog_nxxxxxxxx - log file with info about the last searching

class WorkLog 
{
private:
	QString m_dir;
	HANDLE m_hfiles[LOG_FILES_NUMBER];
	QString m_logs[LOG_FILES_NUMBER];
	CRITICAL_SECTION m_csec[LOG_FILES_NUMBER];

protected:
	WorkLog();

	bool createWorkDirectory(const QString dir = DEFAULT_WORKLOG_DIR_NAME);
	bool initLog(ulong index, QString filename);
	bool createLogs();
	

public:

	bool printmain(const QString);
	bool printmain(const char*);
	
	// Prints information about current running scan session
	bool printscan(const char*);

	static WorkLog& GetLog()
	{
		static WorkLog wrklog;
		return wrklog;
	}

	~WorkLog();
};


#endif
