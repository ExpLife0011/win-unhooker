
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#include "Window.h"
#include <qtextcodec.h>
#include <QMouseEvent>
#include <qvariant.h>
#include <QTextStream>

using namespace Memory;


ui_client::ui_client(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags),
	m_cleaner(new Cleaner()),
	m_session(NULL),
	m_cntxTrustedApp(new CntxMenuTrustedApp()),
	m_cntxProtectedLib(new CntxMenuProtectedLib()),
	m_cmScanObj(new CM_ScanTree()),
	m_cmQuarantine(new CM_Quarantine()),
	m_cnMenuTray(new CM_Tray()),
	m_storage(),
	m_settings(new Settings())
{
	bool state = false;
	m_Gui.setupUi(this);

	// Add main node
	m_pSysLib_Item = new QTreeWidgetItem();
	m_pSysLib_Item->setText(0, QObject::tr("System DLLs"));
	m_pSysLib_Item->setIcon(0, UiResources::GetMe().icoDll());
	m_Gui.WgtSettings().WgtProtectedLibs().TreeOfProtectedLibs()->insertTopLevelItem(
		m_Gui.WgtSettings().WgtProtectedLibs().TreeOfProtectedLibs()->topLevelItemCount(),
		m_pSysLib_Item);

	// Init tray
	trayIcon = new QSystemTrayIcon();
	trayIcon->setContextMenu(m_cnMenuTray->Get());
	trayIcon->setIcon(UiResources::GetMe().icoHome());
	trayIcon->setToolTip("Security");
	trayIcon->show();

	// Connects to the 'Home page' tab
	connect(m_Gui.WgtHome().StartScan(), SIGNAL(clicked()), this, SLOT(slotUMRD1()));

	//Connects to the 'Scanner' tab
	connect(m_Gui.WgtScanner().Pause(),
		SIGNAL(clicked()),
		this,
		SLOT(HandlerPauseClick()));

	connect(m_Gui.WgtScanner().Stop(),
		SIGNAL(clicked()),
		this,
		SLOT(HandlerStopClick()));

	connect(m_Gui.WgtScanner().TreeFoundObjects(),
		SIGNAL(itemClicked(QTreeWidgetItem*,int)),
		this,
		SLOT(HandlerShowCntx_FoundObject(QTreeWidgetItem*,int)));

	//connect(m_Gui.m_btn_do_infect, SIGNAL(clicked()), this, SLOT(slotRemoveAllHooks()));

	// Object in tree
	connect(trayIcon,
		SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
		this,
		SLOT(showHide(QSystemTrayIcon::ActivationReason)));
	

	// TAB: Protected libraries
	connect(m_Gui.WgtSettings().WgtProtectedLibs().RemoveAll(),
		SIGNAL(clicked()),
		this,
		SLOT(HandlerCleanOutProtectedLibs()));

	connect(m_Gui.WgtSettings().WgtProtectedLibs().AddLibrary(),
		SIGNAL(clicked()),
		this,
		SLOT(HandlerCmdAddProtectedLib()));

	connect(m_Gui.WgtSettings().WgtProtectedLibs().LibraryName(),
		SIGNAL(returnPressed()),
		this,
		SLOT(HandlerCmdAddProtectedLib()));

	connect(m_Gui.WgtSettings().WgtProtectedLibs().TreeOfProtectedLibs(),
		SIGNAL(itemClicked(QTreeWidgetItem*,int)),
		this,
		SLOT(HandlerShowCntx_ProtectedLib(QTreeWidgetItem*,int)));

	connect(this->m_cntxProtectedLib,
		SIGNAL(Remove(QTreeWidgetItem*,ulong)),
		this,
		SLOT(HandlerRemoveProtectedLib(QTreeWidgetItem*,ulong)));

	connect(this->m_settings,
		SIGNAL(ProtectedLibLoaded(QString)),
		this,
		SLOT(HandlerAddProtectedLibToTree(QString)));

	//////////////////////////////////////////////////////////////////////////
	// Trusted applications

	connect(Gui().WgtSettings().WgtTrustedApps().RemoveAll(),
		SIGNAL(clicked()),
		this,
		SLOT(HandlerCleanOutTrustedApps()));

	connect(Gui().WgtSettings().WgtTrustedApps().AddApp(),
		SIGNAL(clicked()),
		this,
		SLOT(HandlerAddTrustedApp()));

	connect(Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps(),
		SIGNAL(itemClicked(QTreeWidgetItem*,int)),
		this,
		SLOT(HandlerShowCntx_TrustedApp(QTreeWidgetItem*,int)));

	connect(this->m_settings,
		SIGNAL(TrustedAppLoaded(QString, PTRUSTED_APP)),
		this,
		SLOT(HandlerTrustedAppLoaded(QString, PTRUSTED_APP)));

	connect(this->m_settings,
		SIGNAL(TrustedAppWasMoved(QString, PTRUSTED_APP, PTRUSTED_APP)),
		this,
		SLOT(HandlerTrustedAppWasMoved(QString, PTRUSTED_APP, PTRUSTED_APP)));

	connect(this->m_cntxTrustedApp,
		SIGNAL(Remove(QTreeWidgetItem*)),
		this,
		SLOT(HandlerRemoveTrustedApp(QTreeWidgetItem*)));

	// tray
	connect(this->m_cnMenuTray, SIGNAL(signalShow()), this, SLOT(show()));
	connect(this->m_cnMenuTray, SIGNAL(signalExit()), this, SLOT(HandlerTrayExit()));

	// scan obj
	connect(m_cmScanObj, SIGNAL(signalUnhook(DetectedItem*)), this, SLOT(HandlerResetIatHook(DetectedItem*)));
	connect(m_cmScanObj, SIGNAL(signalInformation(DetectedItem*)), this, SLOT(HandlerShowInfoAboutObject(DetectedItem*)));
	connect(m_cmScanObj, SIGNAL(signalDeleteFile(DetectedItem*)), this, SLOT(HandlerDeleteObject(DetectedItem*)));
	connect(m_cmScanObj, SIGNAL(signalTrustTo(DetectedItem*)), this, SLOT(HandlerTrustTo(DetectedItem*)));

	// settings
	connect(m_Gui.WgtSettings().WgtCommonSettings().UseQuarantine(),
		SIGNAL(stateChanged(int)),
		this,
		SLOT(HandlerEnableQuarantine(int)));

	connect(m_Gui.WgtSettings().WgtCommonSettings().UseHeuristic(),
		SIGNAL(stateChanged(int)),
		this,
		SLOT(HandlerEnableHeuristic(int)));

	connect(m_Gui.WgtSettings().WgtCommonSettings().UseProtectLibs(),
		SIGNAL(stateChanged(int)),
		this,
		SLOT(HandlerEnableProtectedLibs(int)));

	// quarantine
	connect(&m_storage,
		SIGNAL(signalNewObject(const QUARANTINE_FILE*)),
		this,
		SLOT(slotQuarantine_NewObject(const QUARANTINE_FILE*)));

	connect(m_Gui.WgtQuarantine().RemovedObjects(),
		SIGNAL(itemClicked(QTreeWidgetItem*,int)),
		this,
		SLOT(HandlerShowCntx_Quarantine(QTreeWidgetItem*,int)));

	connect(m_cmQuarantine,
		SIGNAL(signalDeleteFile(QTreeWidgetItem*)),
		this,
		SLOT(slotQuarantine_Remove(QTreeWidgetItem*)));

	connect(m_cmQuarantine,
		SIGNAL(signalRecovery(QTreeWidgetItem*)),
		this,
		SLOT(slotQuarantine_BackUp(QTreeWidgetItem*)));

	connect(m_cmQuarantine,
		SIGNAL(signalInfo(QTreeWidgetItem*)),
		this,
		SLOT(slotQuarantine_Info(QTreeWidgetItem*)));

	enabledButtons(FALSE);
	InitializeCriticalSection(&csec_0);

	// load settings
	state = m_settings->Load();
	WorkLog::GetLog().printmain(state ? "settings were loaded successfully":"settings weren't loaded");

	m_settings->EmitProtectedLibraries();
	m_settings->EmitTrustedApps();

	// Loads files to quarantine
	state = m_storage.Load();
	WorkLog::GetLog().printmain(state ? "quarantine was loaded successfully" : "quarantine wasn't loaded");

	// Initializes UI components from settings
	Gui().WgtSettings().WgtCommonSettings().UseQuarantine()->setCheckState(m_settings->UseQuarantine() ? Qt::Checked : Qt::Unchecked);
	Gui().WgtSettings().WgtCommonSettings().UseProtectLibs()->setCheckState(m_settings->UseProtectingIATList() ? Qt::Checked : Qt::Unchecked);
	Gui().WgtSettings().WgtCommonSettings().UseHeuristic()->setCheckState(m_settings->UseHeuristic() ? Qt::Checked : Qt::Unchecked);

	WorkLog::GetLog().printmain("The Program was loaded!");

	// QWidget::setWindowFlags(Qt::WindowFlags::enum_type::Window|
	// Qt::WindowFlags::enum_type::CustomizeWindowHint);
}

void ui_client::slotUMRD1()
{
	enabledButtons(TRUE);
	Gui().WgtHome().StartScan()->setEnabled(FALSE);
	Gui().GetMenu()->setCurrentIndex(SCAN_TAB);

	if(!m_session)
	{
		HandlerChangedStatus("initialize...");
		Gui().WgtScanner().TreeFoundObjects()->clear();
		Gui().WgtScanner().Progress()->setValue(0);
		this->m_session = new Security();

		// Sends configurations settings
		sendScanOptions();
		connectUiToSecurity(m_session);

		// run searching process
		m_session->start();

		// enable buttons
		Gui().WgtScanner().Pause()->setEnabled(TRUE);
		Gui().WgtScanner().Stop()->setEnabled(TRUE);
	} else
	{
		// Session was created then close and create new
		delete this->m_session;
		this->m_session = NULL;
		this->slotUMRD1();
	}
}

// scanner settings
void ui_client::sendScanOptions()  const
{
	this->m_session->EnableLookupApiHooks(m_settings->UseProtectingIATList());
	
	// Builds list of protected libs
	if(m_settings->UseProtectingIATList())
	{
		for(int i=0; i<m_pSysLib_Item->childCount(); i++)
		{
			this->m_session->AddProtectedIAT(m_pSysLib_Item->child(i)->text(0).toLower());
		}
	}
}

void ui_client::HandlerPauseClick()
{
	if(!m_session){
		return;
	}

	// continue -to- pause
	if(m_session->Running())
	{
		m_session->Suspend();
		m_Gui.WgtScanner().Pause()->setText(QObject::tr("Resume"));
		m_Gui.WgtScanner().Pause()->setIcon(UiResources::GetMe().icoStart());
	} else
	{
		m_session->Resume();
		m_Gui.WgtScanner().Pause()->setText(QObject::tr("Pause"));
		m_Gui.WgtScanner().Pause()->setIcon(UiResources::GetMe().icoPause());
	}
}

void ui_client::HandlerStopClick()
{
	if(!m_session) return;

	m_session->Stop();

	if(!m_session->Running()) m_session->Resume();

	// SCAN TAB
	m_Gui.WgtScanner().Pause()->setEnabled(FALSE);
	m_Gui.WgtScanner().Stop()->setEnabled(FALSE);
	
	// HOME TAB
	m_Gui.WgtHome().StartScan()->setEnabled(TRUE);
}

void ui_client::HandlerMsgHandler(long ucode)
{
	RefreshObjectsScanned();
	RefreshCounterFoundObjects();

	switch(ucode)
	{

	case STOP_SECURITY_0:
		m_Gui.WgtScanner().Progress()->setValue(100);
		
		// SCAN TAB
		m_Gui.WgtScanner().Pause()->setEnabled(FALSE);
		m_Gui.WgtScanner().Stop()->setEnabled(FALSE);

		// HOME TAB
		m_Gui.WgtHome().StartScan()->setEnabled(TRUE);
		break;

	default:
		break;
	}
}

// Deletes all suspected objects from the system
void ui_client::slotRemoveAllHooks()
{
	if(!m_Gui.WgtScanner().TreeFoundObjects())
		return;

	MessageBoxA(0, "ddd", "dwedqw", 0);

	m_cleaner->CleanAll(m_Gui.WgtScanner().TreeFoundObjects());
}

void ui_client::showHide(QSystemTrayIcon::ActivationReason r)
{
	if (r == QSystemTrayIcon::Trigger)
	{  //если нажато левой кнопкой продолжаем

		if (!this->isVisible())
		{  //если окно было не видимо - отображаем его
			this->show();
		} else {
			this->hide();
		}
	} else if(r == QSystemTrayIcon::Context)
	{
		// показать контекстное меню
		//MessageBoxA(0,"QMenu", CAPTION_TRAY, MB_OK);
	}
}

// build context menu for trusted areas
void ui_client::HandlerShowCntx_ProtectedLib(QTreeWidgetItem * item, int column)
{
	// root is ignored
	if(item == m_pSysLib_Item) {
		return;
	}

	// Shows menu only for system and trusted library
	if(m_Gui.WgtSettings().WgtProtectedLibs().TreeOfProtectedLibs()->RightButtonClicked())
	{
		if(item->parent() == m_pSysLib_Item){
			m_cntxProtectedLib->ShowMenu(item);
		}
	}
}

void ui_client::HandlerShowCntx_TrustedApp(QTreeWidgetItem * item, int column)
{
	if(m_Gui.WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->RightButtonClicked())
	{
		m_cntxTrustedApp->ShowMenu(item);
	}
}

void ui_client::HandlerShowCntx_Quarantine(QTreeWidgetItem * item, int column)
{
	if(m_Gui.WgtQuarantine().RemovedObjects()->RightButtonClicked())
	{
		m_cmQuarantine->ShowMenu(item);
	}
}

void ui_client::HandlerShowCntx_FoundObject(QTreeWidgetItem* item, int column )
{
	if(m_Gui.WgtScanner().TreeFoundObjects()->RightButtonClicked())
	{
		m_cmScanObj->ShowMenu((DetectedItem*)item);
	}
}

void ui_client::HandlerTrayExit()
{
	this->close();
}

// Shows current status
void ui_client::HandlerChangedStatus(QString s)
{
	m_Gui.WgtScanner().Status()->setText(s);

	RefreshObjectsScanned();
	RefreshCounterFoundObjects();
}

void ui_client::connectUiToSecurity(const Security* pSecurity)
{
	connect(pSecurity,
		SIGNAL(changedStatus(QString)),
		this,
		SLOT(HandlerChangedStatus(QString))
		/*,Qt::DirectConnection*/);

	connect(pSecurity,
		SIGNAL(changedProgress(int)),
		m_Gui.WgtScanner().Progress(),
		SLOT(setValue(int)));

	connect(pSecurity,
		SIGNAL(sendMsg(long)),
		this,
		SLOT(HandlerMsgHandler(long)));

	connect(pSecurity,
		SIGNAL(foundWinApiHook(const IAT_HOOK*)),
		this,
		SLOT(HandlerFoundWinApiHook(const IAT_HOOK*)),
		Qt::DirectConnection);

	connect(pSecurity,
		SIGNAL(foundHeurObject(QString, const HEUR_FILE_DESCR*)),
		this,
		SLOT(HandlerHeurFound(QString, const HEUR_FILE_DESCR*)),
		Qt::DirectConnection);

	connect(pSecurity,
		SIGNAL(foundHiddenObject(QString)),
		this,
		SLOT(HandlerFoundHiddenObject(QString)),
		Qt::DirectConnection);

	connect(pSecurity,
		SIGNAL(foundSsdtHook(const SSDT_HK*)),
		this,
		SLOT(HandlerFoundSsdtHook(const SSDT_HK*)),
		Qt::DirectConnection);
}

void ui_client::enabledButtons(BOOL f)
{
	m_Gui.WgtScanner().Pause()->setEnabled(f);
	m_Gui.WgtScanner().Stop()->setEnabled(f);
	m_Gui.WgtScanner().RemoveAll()->setEnabled(f);
}

Ui::ui_clientClass& ui_client::Gui()
{
	return m_Gui;
}

void ui_client::closeApp()
{
	DeleteCriticalSection(&csec_0);

	// pSession;
	delete		m_pSysLib_Item;
	delete		trayIcon;
	delete		m_cntxProtectedLib;
	delete		m_cnMenuTray;
	delete		m_settings;
}

ui_client::~ui_client()
{
	this->closeApp();
}
