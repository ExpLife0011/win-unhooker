
//      (c)VsoftLab 2006 - 2014
//		Author: burluckij@gmail.com	


#ifndef UIBUILDER_H
#define UIBUILDER_H

#include <QObject.h>
#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QCheckBox>
#include <QtGui/QGroupBox>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QProgressBar>
#include <QtGui/QPushButton>
#include <QtGui/QTabWidget>
#include <QtGui/QTreeWidget>
#include <QtGui/QWidget>
#include <QMouseEvent>
#include <QVBoxLayout>
#include <QComboBox>

#include "extended_tree.h"

#define USE_FLAT_BUTTONS		TRUE
#define BUTTONS_SIZE			(QSize(24,24))

QT_BEGIN_NAMESPACE

class QGridLayout;
class QHBoxLayout;
class QVBoxLayout;

class TrustedAppsWidget: public QWidget{
	Q_OBJECT
private:
	QPushButton		*m_addApp;
	QPushButton		*m_removeAll;
	ExtendedTree	*m_treeTrustedApps;

public:
	QPushButton* AddApp() const {
		return m_addApp;
	}

	QPushButton* RemoveAll() const {
		return m_removeAll;
	}

	ExtendedTree* TreeOfTrustedApps() const {
		return m_treeTrustedApps;
	}

	TrustedAppsWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class ProtectedLibsWidget: public QWidget {
	Q_OBJECT
private:
	QGroupBox		*m_GroupBox;
	QPushButton		*m_addLib;
	QPushButton		*m_removeAll;
	QLineEdit		*m_libName;
	ExtendedTree	*m_treeProtectedLibs;

public:

	QPushButton* AddLibrary() const {
		return m_addLib;
	}

	QPushButton* RemoveAll() const {
		return m_removeAll;
	}

	QLineEdit* LibraryName() const {
		return m_libName;
	}

	ExtendedTree* TreeOfProtectedLibs() const {
		return m_treeProtectedLibs;
	}

	ProtectedLibsWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class CommonSettingsWidget: public QWidget{
	Q_OBJECT
private:
	QCheckBox		*m_quarantine;
	QCheckBox		*m_heuristic;
	QCheckBox		*m_protectLibs;
	QComboBox		*m_language_select;
	QLabel			*m_language;

public:

	QComboBox* LanguageSelect() const{
		return m_language_select;
	}

	QCheckBox* UseQuarantine() const {
		return m_quarantine;
	}

	QCheckBox* UseHeuristic() const {
		return m_heuristic;
	}

	QCheckBox* UseProtectLibs() const {
		return m_protectLibs;
	}

	CommonSettingsWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class ScannerWidget: public QWidget {
	Q_OBJECT
private:
	QGroupBox	*m_GroupBox;
	QPushButton *m_pause;
	QPushButton *m_stop;
	QPushButton *m_removeAll;
	ExtendedTree	*m_treeFoundObjects;

	QProgressBar *m_progress;
	QLabel *m_status;
	QLabel *m_time_elapsed;
	QLabel *m_time_elapsed_n;
	QLabel *m_scanned_objects;
	QLabel *m_scanned_objects_n;
	QLabel *m_found_objects;
	QLabel *m_found_objects_n;

public:

	ExtendedTree* TreeFoundObjects() const {
		return m_treeFoundObjects;
	}

	QLabel* TimeElapsed() const{
		return m_time_elapsed_n;
	}

	QLabel* ScannedObjects() const{
		return m_scanned_objects_n;
	}

	QLabel* FoundObjects() const{
		return m_found_objects_n;
	}

	QPushButton* Pause() const {
		return m_pause;
	}

	QPushButton* Stop() const {
		return m_stop;
	}

	QProgressBar* Progress() const {
		return m_progress;
	}

	QLabel* Status() const {
		return m_status;
	}

	QPushButton* RemoveAll() const {
		return m_removeAll;
	}

	ScannerWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class HomeWidget: public QWidget {
	Q_OBJECT
private:
	QPushButton *m_startScan;

public:

	QPushButton* StartScan() const {
		return m_startScan;
	}

	HomeWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class QuarantineWidget: public QWidget {
	Q_OBJECT
private:
	QGroupBox	*m_GroupBox;
	ExtendedTree *m_treeRemovedObjects;

public:

	ExtendedTree* RemovedObjects() const {
		return m_treeRemovedObjects;
	}

	QuarantineWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class SettingsWidget: public QWidget{
	Q_OBJECT
private:
	QTabWidget *m_SettingsSubWindows;

	CommonSettingsWidget *m_wgtWindowCommon;
	TrustedAppsWidget *m_wgtWindowTrustedApps;
	ProtectedLibsWidget *m_wgtWindowProtectedLibs;

public:

	CommonSettingsWidget& WgtCommonSettings() const {
		return *m_wgtWindowCommon;
	}

	TrustedAppsWidget& WgtTrustedApps() const {
		return *m_wgtWindowTrustedApps;
	}

	ProtectedLibsWidget& WgtProtectedLibs() const {
		return *m_wgtWindowProtectedLibs;
	}

	SettingsWidget(QWidget *parent = 0, Qt::WFlags flags = 0);
};

class Ui_ui_clientClass
{
private:
	void InitMainPage();
	void InitScanPage();
	void InitOptionsPage();
	void InitQuarantinePage();
	
	QTabWidget *m_Menu;

	// Main tabs
	HomeWidget *m_pageHome;
	ScannerWidget *m_pageScan;
	SettingsWidget *m_pageOptions;
	QuarantineWidget *m_pageQuarantine;

public:
	// Content
	ExtendedTree *m_TreeTrustedApps;

	QTabWidget* GetMenu() const {
		return m_Menu;
	}

	HomeWidget& WgtHome() const {
		return *m_pageHome;
	}

	ScannerWidget& WgtScanner() const {
		return *m_pageScan;
	}

	SettingsWidget& WgtSettings() const {
		return *m_pageOptions;
	}

	QuarantineWidget& WgtQuarantine() const {
		return *m_pageQuarantine;
	}
	
	void setupUi(QMainWindow *ui_clientClass);

	// i inherited this code from ui generator
	void retranslateUi(QMainWindow *ui_clientClass)
	{
		ui_clientClass->setWindowTitle("Smart&Fast Security -  Anti-Rootkit for Windows");

#ifndef QT_NO_TOOLTIP
		ui_clientClass->setToolTip(QString());
#endif // QT_NO_TOOLTIP

	} // retranslateUi

};

namespace Ui {
	class ui_clientClass: public Ui_ui_clientClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UIBUILDER_H

