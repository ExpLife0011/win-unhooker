
//	(c) Burlutsky Stanislav
//	Author: burluckij@gmail.com


#ifndef UI_CLIENT_H
#define UI_CLIENT_H

//#include "ui_ui_client.h"
#include "UiBuilder.h"
#include "ui_objects.h"
#include "System.h"
#include "pe.h"
#include "security.h"
#include "cleaner.h"
#include "RefObject.h"
#include "quarantine.h"
#include "system_tray.h"
#include "cntxmenu_settings.h"
#include "detected_object.h"
#include "quarantine_object.h"
#include "extended_tree.h"
#include "settings.h"
#include "worklog.h"
#include "heuristic.h"

class ui_client : public QMainWindow, protected CBase
{
	Q_OBJECT

public:
	ui_client(QWidget *parent = 0, Qt::WFlags flags = 0);
	~ui_client();
	
private slots:
	void	HandlerPauseClick();
	void	HandlerStopClick();
	
	void	HandlerChangedStatus(QString);
	void	HandlerMsgHandler(long ucode);
	
	void	HandlerShowCntx_TrustedApp(QTreeWidgetItem * item, int column);
	void	HandlerShowCntx_ProtectedLib(QTreeWidgetItem * item, int column);
	void	HandlerShowCntx_FoundObject(QTreeWidgetItem * item, int column);

	void	HandlerTrayExit(); // call from tray
	void	slotUMRD1(); // start scan

	void	showHide(QSystemTrayIcon::ActivationReason);

	// scan tree

	// Removes hook from IAT
	void	HandlerResetIatHook(DetectedItem*);

	// Shows a window with information about found object
	void	HandlerShowInfoAboutObject(DetectedItem*);

	// Removes a file from system, automatic saves in quarantine
	void	HandlerDeleteObject(DetectedItem*);

	// Receives information about found objects
	void	HandlerHeurFound(QString, const HEUR_FILE_DESCR*);
	void	HandlerFoundSsdtHook(const SSDT_HK*);
	void	HandlerFoundWinApiHook(const IAT_HOOK*);
	void	HandlerFoundHiddenObject(QString);

	void	slotRemoveAllHooks();

	// settings
	void	HandlerAddProtectedLibToTree(QString);
	void	HandlerCmdAddProtectedLib();
	void	HandlerRemoveProtectedLib(QTreeWidgetItem*, ulong);
	bool	HandlerEnableQuarantine(int);
	bool	HandlerEnableProtectedLibs(int);
	bool	HandlerEnableFileLimits(int);
	bool	HandlerEnableHeuristic(int);
	void	HandlerTrustTo(DetectedItem*);
	void	HandlerAddTrustedApp();
	void	HandlerRemoveTrustedApp(QTreeWidgetItem*);
	void	HandlerTrustedAppLoaded(QString, PTRUSTED_APP);
	void	HandlerTrustedAppWasMoved(QString, PTRUSTED_APP, PTRUSTED_APP);
	void	HandlerCleanOutProtectedLibs();
	void	HandlerCleanOutTrustedApps();

	// quarantine
	void	slotQuarantine_NewObject(const QUARANTINE_FILE* pqf);
	void	slotQuarantine_Remove(QTreeWidgetItem* qItem);
	void	slotQuarantine_BackUp(QTreeWidgetItem* qItem);
	void	HandlerShowCntx_Quarantine(QTreeWidgetItem * item, int column);
	void	slotQuarantine_Info(QTreeWidgetItem* item);

private:
	void	RefreshObjectsScanned();
	void	RefreshCounterFoundObjects();
	void	connectUiToSecurity(const Security* pSecurity);
	QString	buildDescriptionString(const INTERCEPTOR* p) const;
	void	AddActivityDescription(DetectedItem* item, const IAT_HOOK* pImportHook);
	void	AddActivityDescription(DetectedItem* item, const HEUR_FILE_DESCR*);
	void	sendScanOptions() const;
	bool	PresentDescription(__in const DetectedItem* item, __in const HEUR_FILE_DESCR* pDescription);

	DetectedItem*	LookupFoundObject(QString) ;
	
	void	closeApp();
	void	enabledButtons(BOOL f);


	Ui::ui_clientClass	m_Gui;
	Ui::ui_clientClass& Gui();

	Quarantine  m_storage;

	Security*			m_session;
	Cleaner*			m_cleaner;
	Settings*			m_settings;

	QSystemTrayIcon		*trayIcon;
	CRITICAL_SECTION	csec_0;
	QTreeWidgetItem*	m_pSysLib_Item;
	
	
	CM_Tray*		m_cnMenuTray;
	CntxMenuProtectedLib*	m_cntxProtectedLib;
	CntxMenuTrustedApp*		m_cntxTrustedApp;
	CM_ScanTree*			m_cmScanObj;
	CM_Quarantine*	m_cmQuarantine;
};

#endif // UI_CLIENT_H
