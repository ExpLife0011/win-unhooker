
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	

#ifndef DETECTED_OBJECT_H
#define DETECTED_OBJECT_H

#include <QtGui/QMainWindow>
#include <QSystemTrayIcon>
#include <QTreeWidget.h>
#include <QTableWidgetItem>
#include <QTableWidget>
#include <QMouseEvent>
#include <qmenu.h>
#include <qmenubar.h>
#include "images.h"
#include "ex_items.h"

class CM_ScanTree: public QWidget{
	Q_OBJECT

private:
	QMenu* contextMenu;
	DetectedItem* item;
	QAction* m_resetHook;
	QAction* m_remove;
	QAction* m_showInfo;
	QAction* m_trustTo;

public:
	CM_ScanTree()
	{
		contextMenu = new QMenu(this);
		m_resetHook = contextMenu->addAction("Reset hook");
		m_remove = contextMenu->addAction("Delete file");
		m_showInfo = contextMenu->addAction("Information");
		m_trustTo = contextMenu->addAction("Trust to");

		m_resetHook->setIcon(UiResources::GetMe().icoOk());
		m_remove->setIcon(UiResources::GetMe().icoRemove());
		m_showInfo->setIcon(UiResources::GetMe().icoInfo());
		m_trustTo->setIcon(UiResources::GetMe().icoAdd());

		connect(contextMenu, SIGNAL(triggered(QAction*)), this, SLOT(slotActivated(QAction*)));
	}

	QMenu* Get()
	{
		return contextMenu;
	}

	// Qualifiers object's type and builds menu
	void ShowMenu(DetectedItem* i)
	{
		if(i->Root()){
			m_resetHook->setEnabled(false);
			m_remove->setEnabled(true);
			m_showInfo->setEnabled(false);
			m_trustTo->setEnabled(true);
		} else {
			m_resetHook->setEnabled(true);
			m_remove->setEnabled(false);
			m_showInfo->setEnabled(true);
			m_trustTo->setEnabled(false);
		}

		item = i;
		contextMenu->exec(QCursor::pos());
	}

signals:
	void signalUnhook(DetectedItem*);
	void signalDeleteFile(DetectedItem*);
	void signalInformation(DetectedItem*);
	void signalTrustTo(DetectedItem*);

public slots:
		void slotActivated(QAction* pAction)
		{
			if(pAction == m_resetHook)
				emit signalUnhook(item);
			else if(pAction == m_remove)
				emit signalDeleteFile(item);
			else if(pAction == m_showInfo)
				emit signalInformation(item);
			else if(pAction == m_trustTo)
				emit signalTrustTo(item);
		}
};

#endif
