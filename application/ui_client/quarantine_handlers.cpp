
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014


#include "window.h"
#include <QFileDialog>
#include <QUrl>

// gets pointer to the information about a file in the quarantine
#define GET_KILLED_PTR(ptrItem, f_ok)		((QUARANTINE_FILE*)ptrItem->data(3, 2).toUInt(&f_ok))

// Removes the file from quarantine and quarantine tree
void ui_client::slotQuarantine_Remove(QTreeWidgetItem* qItem)
{
	bool f_ok = false;
	PQUARANTINE_FILE pKilledInf = GET_KILLED_PTR(qItem, f_ok);

	if(f_ok)
	{
		if(f_ok = m_storage.DeleteObject(pKilledInf->killedName))
		{
			delete qItem;
		}
	}
}

// backups and deletes a file from the quarantine 
void ui_client::slotQuarantine_BackUp(QTreeWidgetItem* qItem)
{
	bool f_ok = false;
	PQUARANTINE_FILE pKilledInf = GET_KILLED_PTR(qItem, f_ok);

	if(f_ok)
	{
		QString fileName = QFileDialog::getSaveFileName(this, tr("Save File"),"", tr("All files (*.)"));
		for(int i = 0; i<fileName.size(); ++i)
		{
			if(fileName[i] == '/')
			{
				fileName[i] = '\\';
			}
		}

		if(f_ok = m_storage.Backup(pKilledInf->killedName, fileName))
		{
			slotQuarantine_Remove(qItem);
		} else
		{
			// fail.
		}
	}
}

// create a new item in the quarantine tree
void ui_client::slotQuarantine_NewObject(const QUARANTINE_FILE* ptrFileInfo)
{
	QTreeWidgetItem* childItem = new QTreeWidgetItem();
	uint p = (uint)ptrFileInfo;
	QVariant context_data(p);
	char szFileSize[128] = "";

	wsprintfA(szFileSize, "%d kb", ptrFileInfo->file_size/1024);

	childItem->setText(0, QString(ptrFileInfo->found_place));
	childItem->setText(1, QString(szFileSize));
	childItem->setText(2, QString(ptrFileInfo->txtTime));

	// save pointer to object
	childItem->setData(3, 2, context_data);
	//p = childItem->data(0, 0).toUInt();

	m_Gui.WgtQuarantine().RemovedObjects()->insertTopLevelItem(m_Gui.WgtQuarantine().RemovedObjects()->topLevelItemCount(),
		childItem);
}

// note(!): in a future have to show custom window
void ui_client::slotQuarantine_Info(QTreeWidgetItem* item)
{
	bool f_ok = false;
	PQUARANTINE_FILE ptrFileInfo = GET_KILLED_PTR(item, f_ok);

	if(f_ok)
	{
		char buffer[1024];

		wsprintfA(buffer, "Date: %s\nFound in: %s\nSize: %d bytes\nName in quarantine: %s\nType: %d\n", 
			ptrFileInfo->txtTime, ptrFileInfo->found_place, ptrFileInfo->file_size,
			ptrFileInfo->killedName, ptrFileInfo->type);

		MessageBoxA(0, buffer, "Info", MB_OK);
	}
}