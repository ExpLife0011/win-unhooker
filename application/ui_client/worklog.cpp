
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#include "worklog.h"
#include <QTime>

bool WorkLog::printmain(const char* szData)
{
	bool result = false;
	DWORD written = 0;

	QString line = QTime::currentTime().toString(Qt::TextDate) + QString(": ") + QString(szData) + QString("\n");

	EnterCriticalSection(&m_csec[MAIN_LOG_INDEX]);
	SetFilePointer(m_hfiles[MAIN_LOG_INDEX], 0, 0, FILE_END);

	result = WriteFile(m_hfiles[MAIN_LOG_INDEX], line.toAscii().constData(),
		CBase::kstrlen(line.toAscii().constData()), &written, 0);

	FlushFileBuffers(m_hfiles[MAIN_LOG_INDEX]);
	LeaveCriticalSection(&m_csec[MAIN_LOG_INDEX]);

	return result;
}

bool WorkLog::printmain(const QString line)
{
	return printmain(line.toAscii().constData());
}

bool WorkLog::createWorkDirectory(const QString dir)
{
	QString sdir;

	if(dir == DEFAULT_WORKLOG_DIR_NAME)
	{
		char currdir[MAX_PATH];

		if(!GetCurrentDirectoryA(sizeof(currdir)/sizeof(char), currdir)){
			return false;
		}

		sdir = QString(currdir) + QString("\\") + QString(dir);
	} else 
	{
		// in this case user must pass full path to the directory
		sdir = QString(dir);
	}

	if(!CreateDirectoryA(sdir.toAscii().constData(), NULL))
	{
		if(GetLastError() != ERROR_ALREADY_EXISTS)
		{
			// unknown error
			return false;
		}
	}

	this->m_dir = sdir;
	return true;
}

bool WorkLog::initLog(ulong index, QString filename)
{
	m_logs[index] = m_dir + QString("\\") + QString(filename) + QString(".log");
	HANDLE hfile = System::CreateOrOpen(m_logs[index]);
	
	if (hfile != INVALID_HANDLE_VALUE)
		m_hfiles[index] = hfile;

	return hfile != INVALID_HANDLE_VALUE;
}

bool WorkLog::createLogs()
{
	HANDLE hfile = INVALID_HANDLE_VALUE;

	CBase::kmemset(this->m_hfiles, 0, sizeof(this->m_hfiles));

// 	// 1. main log
// 	initLog(MAIN_LOG_INDEX, MAIN_LOG);
// 
// 	// 2. scan log
// 	initLog(SCAN_LOG_INDEX, SCAN_LOG);

	return initLog(MAIN_LOG_INDEX, MAIN_LOG) && initLog(SCAN_LOG_INDEX, SCAN_LOG);
}

WorkLog::~WorkLog()
{
	for(int i = 0; i < LOG_FILES_NUMBER; ++i)
	{
		if(m_hfiles[i] || (m_hfiles!=INVALID_HANDLE_VALUE)) CloseHandle(m_hfiles[i]);
		DeleteCriticalSection(&m_csec[i]);
	}
}

WorkLog::WorkLog()
{
	for(int i = 0; i < LOG_FILES_NUMBER; ++i)
	{
		InitializeCriticalSection(&this->m_csec[i]);
	}

	createWorkDirectory();

	createLogs();
}
