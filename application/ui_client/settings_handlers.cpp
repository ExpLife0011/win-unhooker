
//      (c)Burlutsky Stanislav 2006 - 2014
//		Author: burluckij@gmail.com	

#include "window.h"
#include <QFileDialog>
#include <QUrl>

void ui_client::HandlerAddProtectedLibToTree(QString library)
{
	QTreeWidgetItem* libNode = new (std::nothrow)QTreeWidgetItem();

	if(!libNode)
		return;

	libNode->setIcon(0, UiResources::GetMe().icoDll());
	libNode->setText(0, library);
	m_pSysLib_Item->addChild(libNode);

	if(m_session && m_session->Running())
		m_session->AddProtectedIAT(library);
}

// Try to add new lib
void ui_client::HandlerCmdAddProtectedLib()
{
	QString library = Gui().WgtSettings().WgtProtectedLibs().LibraryName()->text().toLower();

	// empty string
	if(Gui().WgtSettings().WgtProtectedLibs().LibraryName()->text().count() == 0)
		return;

	// compares with exists libs
	for(int i=0; i<m_pSysLib_Item->childCount(); i++)
	{
		if(m_pSysLib_Item->child(i)->text(0).toLower() == library)
		{
			return;
		}
	}

	Gui().WgtSettings().WgtProtectedLibs().LibraryName()->clear();
	m_settings->AddProtectedLibrary(library);
}

// deletes objects from system&trusted tree
void ui_client::HandlerRemoveProtectedLib(QTreeWidgetItem* item, ulong code)
{
	QByteArray r = item->text(0).toAscii();

	if(code == SYSLIB_ACTIVE)
		m_settings->RemoveProtectedLibrary(item->text(0).toAscii());

	delete item;
}

bool ui_client::HandlerEnableQuarantine(int state)
{
	return m_settings->EnableQuarantine(state == Qt::Checked);
}

bool ui_client::HandlerEnableProtectedLibs(int state)
{
	return m_settings->EnableProtectingIATList(state == Qt::Checked);
}

bool ui_client::HandlerEnableFileLimits(int state)
{
	return m_settings->EnableFileLimits(state == Qt::Checked);
}

bool ui_client::HandlerEnableHeuristic(int state)
{
	return m_settings->EnableHeuristic(state == Qt::Checked);
}

void ui_client::HandlerCleanOutProtectedLibs()
{
	bool cleaned = m_settings->CleanOutProtectedLibs();

	if(cleaned)
	{
		Gui().WgtSettings().WgtProtectedLibs().TreeOfProtectedLibs()->clear();
	} else {
		MessageBoxA(0, "error clean out", "error HandlerCleanOutProtectedLibs", 0);
	}
}

//////////////////////////////////////////////////////////////////////////
// Trusted applications 
//////////////////////////////////////////////////////////////////////////

void ui_client::HandlerTrustedAppLoaded(QString filePath, PTRUSTED_APP pDescription)
{
	TrustedAppItem* newApp = new TrustedAppItem(pDescription);
	
	// All files: exe, dll, sys - will have different icons!
	QIcon iconApp;
	filePath = filePath.toLower();

	if(filePath.indexOf(".exe", Qt::CaseInsensitive) != -1)
	{
		iconApp = UiResources::GetMe().icoExe16();
	} else if(filePath.indexOf(".sys", Qt::CaseInsensitive) != -1)
	{
		iconApp = UiResources::GetMe().icoDll();
	} else if(filePath.indexOf(".dll", Qt::CaseInsensitive) != -1)
	{
		iconApp = UiResources::GetMe().icoDllBlack();
	} else {
		iconApp = UiResources::GetMe().icoNoset();
	}

	//newApp->AppDescription(pDescription);
	newApp->setIcon(0, iconApp);
	newApp->setText(0, QString(filePath));

	// Add new application to the tree in view model
	Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->insertTopLevelItem(
		Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->topLevelItemCount(),
		newApp);
}

void ui_client::HandlerAddTrustedApp()
{
	QString fileName = QFileDialog::getOpenFileName(this);

	if (!fileName.length()){
		return;
	}

	for(int i = 0; i<fileName.size(); ++i){
		if(fileName[i] == '/'){
			fileName[i] = '\\';
		}
	}

	m_settings->AddTrustedApp(fileName);
}

void ui_client::HandlerRemoveTrustedApp(QTreeWidgetItem* pItem)
{
	TrustedAppItem* pitem = dynamic_cast<TrustedAppItem*>(pItem);

	if(!pitem) return;

	if(m_settings->RemoveTrustedApp(pitem->text(0)))
	{
		delete pItem;
	} else 
	{
		MessageBoxA(0, pitem->text(0).toAscii().constData(), "error RemoveTrustedApp", 0);
	}
}

void ui_client::HandlerTrustedAppWasMoved(QString appPath, PTRUSTED_APP pOldPosition, PTRUSTED_APP pNewPosition)
{
	appPath = appPath.toLower();

	for(int i = 0; i < Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->topLevelItemCount(); i++)
	{	
		TrustedAppItem* itemApp = dynamic_cast<TrustedAppItem*>(Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->topLevelItem(i));

		if(itemApp->text(0).toLower() == appPath)
		{
// 			if (itemApp->AppDescription() == pOldPosition)
// 			{
// 				itemApp->AppDescription(pNewPosition);
// 			}
			// TEST VERSION
			itemApp->AppDescription(pNewPosition);
			return;
		}
	}
}

void ui_client::HandlerCleanOutTrustedApps()
{
	bool cleaned = m_settings->CleanOutTrustedApps();

	if(cleaned)
	{
		Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->clear();
	} else {
		MessageBoxA(0, "error clean out", "error HandlerCleanOutTrustedApps", 0);
	}
}
