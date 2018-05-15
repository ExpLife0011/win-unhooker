
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#include "window.h"

using namespace Memory;

#define ADD_ROOT_OBJECT(node_)	(m_Gui.WgtScanner().TreeFoundObjects()->insertTopLevelItem(m_Gui.WgtScanner().TreeFoundObjects()->topLevelItemCount(), node_))

void ui_client::RefreshCounterFoundObjects()
{
	ulong found_objects = Gui().WgtScanner().TreeFoundObjects()->topLevelItemCount();
	Gui().WgtScanner().FoundObjects()->setText(QString("%1").arg(found_objects));
}

void ui_client::RefreshObjectsScanned()
{
	QString n_scanned("0");

	if(m_session){
		n_scanned = QString("%1").arg(m_session->ObjectsScanned());
	}

	m_Gui.WgtScanner().ScannedObjects()->setText(n_scanned);
}

// Adds to early created object a string with characteristic of activity
void ui_client::AddActivityDescription(DetectedItem* item, const IAT_HOOK* pImportHook)
{
	DetectedItem* childItem = new DetectedItem();
	char szDescription[1024];
	szDescription[0] = 0;

	char* frmt_str;

	if(pImportHook->hideObject)
		frmt_str = "%s @ %s: %s.%s(%x) -> %x (hidden!)";
	else
		frmt_str = "%s @ %s:%s.%s(%x) -> %x";

	wsprintfA(szDescription,
		frmt_str,
		pImportHook->szProc,
		pImportHook->szModule,
		pImportHook->szLibName,
		pImportHook->szApiName,
		pImportHook->originalApiAddr,
		pImportHook->pHookCall);

	childItem->SetRed();
	childItem->Root(false);
	childItem->setText(0, QString(szDescription));
	childItem->setIcon(0, UiResources::GetMe().icoWarning());
	childItem->SaveDescrData(pImportHook, sizeof(IAT_HOOK));

	item->addChild(childItem);
}

bool ui_client::PresentDescription(__in const DetectedItem* item, __in const HEUR_FILE_DESCR* pDescription)
{
	QString description = HeurGetDescription(pDescription);

	for(int i = 0; i < item->childCount(); i++)
	{
		if(DetectedItem* infItem = (DetectedItem*)item->child(i))
		{
			if (infItem->text(0) == description)
			{
				return true;
			}
		}
	}

	return false;
}

void ui_client::AddActivityDescription(DetectedItem* item, const HEUR_FILE_DESCR* pDescription)
{
	DetectedItem* childItem = NULL;
	QString description = HeurGetDescription(pDescription);

	if (PresentDescription(item, pDescription))
		return;

	childItem = new DetectedItem();
	childItem->SetRed();
	childItem->Root(false);
	childItem->setText(0, description);
	childItem->setIcon(0, UiResources::GetMe().icoWarning());
	childItem->SaveDescrData(pDescription, sizeof(HEUR_FILE_DESCR));

	item->addChild(childItem);
}

DetectedItem*	ui_client::LookupFoundObject(QString filePath)
{
	filePath = filePath.toLower();

	// Searching through the already known threats(files)
	for(int i=0; i < m_Gui.WgtScanner().TreeFoundObjects()->topLevelItemCount(); i++)
	{	
		DetectedItem* objectItem = dynamic_cast<DetectedItem*>(m_Gui.WgtScanner().TreeFoundObjects()->topLevelItem(i));

		// each kind of threats have to be processed differently!
		// ...

		// All strings have to be processed in the lowercase (important that all strings were compared in the same register )
		if(objectItem->text(0).toLower() == filePath)
		{
			return objectItem;
		}
	}

	return NULL;
}

void ui_client::HandlerHeurFound(QString filePath, const HEUR_FILE_DESCR* pDesc)
{
	DetectedItem* suspectedObjectItem = NULL;

	if(DetectedItem* objectItem = LookupFoundObject(filePath))
	{
		AddActivityDescription(objectItem, pDesc);
		return;
	}

	suspectedObjectItem = new DetectedItem();
	suspectedObjectItem->Root(TRUE);
	suspectedObjectItem->setIcon(0, UiResources::GetMe().icoQuarantine());
	suspectedObjectItem->setText(0, filePath);

	ADD_ROOT_OBJECT(suspectedObjectItem);
	AddActivityDescription(suspectedObjectItem, pDesc);
	RefreshCounterFoundObjects();
}

void ui_client::HandlerFoundWinApiHook(const IAT_HOOK* pFoundObject)
{
	QString filePath = QString(pFoundObject->szHookLibrary)/*.toLower()*/;

	if(DetectedItem* objectItem = LookupFoundObject(filePath))
	{
		AddActivityDescription(objectItem, pFoundObject);
		return;
	}

	// Create new root node
	DetectedItem *rootItem = new DetectedItem();
	rootItem->Root(TRUE);

	// The node without characteristics, only file on disk
	rootItem->setIcon(0, UiResources::GetMe().icoNoset());
	rootItem->setText(0, QString(pFoundObject->szHookLibrary));

	ADD_ROOT_OBJECT(rootItem);
	HandlerFoundWinApiHook(pFoundObject);
	RefreshCounterFoundObjects();
}

void ui_client::HandlerFoundSsdtHook(const SSDT_HK* hook)
{
	QString filePath = QString(hook->rtkfile);
	DetectedItem* item = LookupFoundObject(filePath);

	// Add new characteristic
	if(item)
	{
		DetectedItem* descrItem = new DetectedItem(SSDT_INTERCEPTOR, false);
		QString obj_description = QString("ssdt[%1] -> interceptor 0x%2 (image 0x%3)")
			.arg(hook->index).arg((ulong)hook->hookproc, 0, 16).arg((ulong)hook->rtkimage, 0, 16);
		
		descrItem->SetRed();
		descrItem->SaveDescrData(hook, sizeof(SSDT_HK));
		descrItem->setText(0, obj_description);
		descrItem->setIcon(0, UiResources::GetMe().icoRemove());
		item->addChild(descrItem);
		return;
	}

	// Create new root node
	// All root nodes have only short description - file path
	DetectedItem *rootItem = new DetectedItem();
	rootItem->Root(TRUE);
	rootItem->setIcon(0, UiResources::GetMe().icoNoset());
	rootItem->setText(0, filePath);

	ADD_ROOT_OBJECT(rootItem);
	HandlerFoundSsdtHook(hook);
	RefreshCounterFoundObjects();
}

void ui_client::HandlerFoundHiddenObject(QString filePath)
{
	DetectedItem* suspectedObjectItem = NULL;

	suspectedObjectItem = new DetectedItem();
	suspectedObjectItem->Root(TRUE);
	suspectedObjectItem->setIcon(0, UiResources::GetMe().icoApplication());
	suspectedObjectItem->setText(0, filePath);

	ADD_ROOT_OBJECT(suspectedObjectItem);
	RefreshCounterFoundObjects();
}

void ui_client::HandlerTrustTo(DetectedItem* pItem)
{
	// If the item was added early, to do nothing
	for(int i = 0; i < Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->topLevelItemCount(); i++)
	{	
		QTreeWidgetItem* itemApp = Gui().WgtSettings().WgtTrustedApps().TreeOfTrustedApps()->topLevelItem(i);

		if(itemApp->text(0).toLower() == pItem->text(0).toLower())
			return;
	}

	bool added = m_settings->AddTrustedApp(pItem->text(0).toLower());

	if(!added)
	{
		WorkLog::GetLog().printmain(QString("%1 was not added in trusted area").arg(pItem->text(0)));
		return;
	}

	pItem->setDisabled(true);
	//delete pItem;
}

// Deletes hook of selected item
void ui_client::HandlerResetIatHook(DetectedItem* item)
{
	PIAT_HOOK phinf = (PIAT_HOOK)item->GetDescrData();

	if (item->GetType() != WIN_API_IMPORT_HOOK){
		return;
	}

	if(m_cleaner->IatReset(phinf))
	{
		item->SetGreen();
		item->setIcon(0, UiResources::GetMe().icoOk());
	}
}

// show information about object
void ui_client::HandlerShowInfoAboutObject(DetectedItem* item)
{
	char message[1024*2];
	message[0] = 0;

	if(item && item->GetDescrData())
	{
		switch (item->GetType())
		{
		case WIN_API_IMPORT_HOOK:
			PIAT_HOOK phook = (PIAT_HOOK)item->GetDescrData();
			wsprintfA(message, "rootkit: %s\nhook routine: 0x%x\nhidden (false or true): %d\n\n"\
				"original library: %s\nfunction name: %s\n"\
				"original address: 0x%x\nprocess: %s(%d)\nmodule: %s\n",

				phook->szHookLibrary,
				phook->pHookCall,
				phook->hideObject,
				phook->szLibName,
				phook->szApiName,
				phook->originalApiAddr,
				phook->szProc,
				phook->pid,
				phook->szModule);

			break;

// 		default:
// 			strcpy(message, "file without info");
// 			break;
		}
	}

	if(message[0])
		MessageBoxA(0, message, "Info", MB_ICONINFORMATION);
}

void ui_client::HandlerDeleteObject(DetectedItem* pObjectItem)
{
	bool saved = false, unhooked = true, unloded = true;
	QString killedFilePath, filepath = pObjectItem->text(0);

	// If quarantine is enabled - automatically save the object
	if(m_settings->UseQuarantine())
	{
		saved = m_storage.AddObject(filepath.toAscii().constData(), &killedFilePath);
	}

	// Reset all hooks if it's necessary
	unhooked = m_cleaner->RemoveAllHooks(pObjectItem);
	if (unhooked)
	{
		WorkLog::GetLog().printmain(QString("%1 all hooks were removed").arg(filepath));

		// Tries to unload object
		unloded = m_cleaner->UnloadObject(filepath.toAscii().constData());
		if(unloded)
		{
			WorkLog::GetLog().printmain(QString("%1 was unloaded from system").arg(filepath));
		} else {
			WorkLog::GetLog().printmain(QString("error: %1 wasn't unloaded from system").arg(filepath));
		}

	} else 
	{
		WorkLog::GetLog().printmain(QString("error: %1 hooks weren't removed").arg(filepath));
	}

	// Delete the object from disk
	if(m_cleaner->RemoveFile(filepath))
	{
		QString remmsg(QString("%1 file was removed").arg(filepath));
		MessageBoxA(0, remmsg.toAscii().constData(), "Removing", MB_OK);

		// !!! Have to remember how delete Item correctly
		delete pObjectItem;

	} else
	{
		// I have to delete early created copy of the object in quarantine
		DeleteFileA(killedFilePath.toAscii().constData());
		QString errmsg(QString("error: %1 was not removed!").arg(filepath));

		// Show simple dialog message to user!
		MessageBoxA(0, errmsg.toAscii().constData(), "Removing", MB_ICONERROR);
	}
}
