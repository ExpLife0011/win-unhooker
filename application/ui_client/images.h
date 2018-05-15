
//      (c)VsoftLab 2006 - 2014
//		Author: burluckij@gmail.com	


#ifndef IMAGES_H
#define IMAGES_H

#include <QtGui/QMainWindow>
#include <QSystemTrayIcon>
#include <QTreeWidget.h>
#include <QTableWidgetItem>
#include <QTableWidget>
#include <QMouseEvent>
#include <qmenu.h>
#include <qmenubar.h>
#include "ui_objects.h"


class UiResources {
private:
	QIcon _icoStart;
	QIcon _icoOptions;
	QIcon _icoPause;
	QIcon _icoStop;
	QIcon _icoHome;
	QIcon _icoQuarantine;
	QIcon _icoReports;
	QIcon _icoScan;
	QIcon _icoInfo;
	QIcon _icoFolder;
	QIcon _icoNoset;
	QIcon _icoOk;
	QIcon _icoWarning;
	QIcon _icoRemove;
	QIcon _icoDll;
	QIcon _icoClose;
	QIcon _icoHelp;
	QIcon _icoCalendar;
	QIcon _icoRecovery;
	QIcon _icoAdd;
	QIcon m_icoApp;
	QIcon m_icoSettings;
	QIcon m_icoDllBlack;
	QIcon m_icoBin;
	QIcon m_icoExe16;
	QIcon m_icoRussian;
	QIcon m_icoEnglish;

protected:
	UiResources():_icoStart(QString(START_ICO)),
		_icoOptions(OPTIONS_ICO),_icoPause(PAUSE_ICO),
		_icoStop(STOP_ICO), _icoHome(HOME_ICO),_icoQuarantine(BAD_OBJECT),
		_icoReports(REPORTS_ICO), _icoScan(SCAN_ICO), _icoInfo(INFO_ICO),
		_icoFolder(FOLDER_ICO), _icoNoset(NOSET_ICO), _icoOk(OK_ICO),
		_icoWarning(WARNING_ICO), _icoRemove(REMOVE_ICO), _icoDll(DLL_ICO),
		_icoClose(CLOSE_ICO), _icoHelp(HELP_ICO), _icoCalendar(CALENDAR_ICO),
		_icoRecovery(RECOVERY_ICO), _icoAdd(ADD_ICO), m_icoApp(APP_ICO),
		m_icoSettings(SETTINGS_ICO), m_icoDllBlack(DLL_BLACK_ICO), m_icoBin(BIN_ICO),
		m_icoExe16(EXE16_ICO), m_icoRussian(RUSSIAN_ICO), m_icoEnglish(ENGLISH_ICO){
	}

private:
	UiResources(const UiResources&);

public:
	const QIcon& icoStart() const {
		return _icoStart;
	}

	const QIcon& icoRussian() const {
		return m_icoRussian;
	}

	const QIcon& icoEnglish() const {
		return m_icoEnglish;
	}

	const QIcon& icoExe16() const {
		return m_icoExe16;
	}

	const QIcon& icoBin() const {
		return m_icoBin;
	}

	const QIcon& icoDllBlack() const {
		return m_icoDllBlack;
	}

	const QIcon& icoSettings() const {
		return m_icoSettings;
	}

	const QIcon& icoApplication() const {
		return m_icoApp;
	}

	const QIcon& icoOptions() const {
		return _icoOptions;
	}

	const QIcon& icoPause() const {
		return _icoPause;
	}

	const QIcon& icoStop() const {
		return _icoStop;
	}

	const QIcon& icoHome() const {
		return _icoHome;
	}

	const QIcon& icoQuarantine() const {
		return _icoQuarantine;
	}

	const QIcon& icoReports() const {
		return _icoReports;
	}

	const QIcon& icoScan() const {
		return _icoScan;
	}

	const QIcon& icoInfo() const {
		return _icoInfo;
	}

	const QIcon& icoFolder() const {
		return _icoFolder;
	}

	const QIcon& icoNoset() const {
		return _icoNoset;
	}

	const QIcon& icoOk() const {
		return _icoOk;
	}

	const QIcon& icoWarning() const {
		return _icoWarning;
	}

	const QIcon& icoRemove() const {
		return _icoRemove;
	}

	const QIcon& icoDll() const {
		return _icoDll;
	}

	const QIcon& icoClose() const {
		return _icoClose;
	}

	const QIcon& icoHelp() const {
		return _icoHelp;
	}

	const QIcon& icoCalendar() const {
		return _icoCalendar;
	}

	const QIcon& icoRecovery() const {
		return _icoRecovery;
	}

	const QIcon& icoAdd() const {
		return _icoAdd;
	}

	static UiResources& GetMe()
	{
		static UiResources uiObjects;
		return uiObjects;
	}

};

#endif
