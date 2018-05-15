
//      (c)Burlutsky Stas 2006 - 2014
//		Author: burluckij@gmail.com	

#ifndef QUARANTINE_OBJECT_H
#define QUARANTINE_OBJECT_H

#include <QtGui/QMainWindow>
#include <QTreeWidget.h>
#include "images.h"
#include "RefObject.h"

class CM_Quarantine: public QWidget{
	Q_OBJECT

private:
	QMenu* contextMenu;
	QTreeWidgetItem* item;
	QAction* qact_Recovery;
	QAction* qact_Remove;
	QAction* qact_Info;

public:
	CM_Quarantine()
	{
		contextMenu = new QMenu(this);
		qact_Recovery = contextMenu->addAction("Recovery");
		qact_Remove = contextMenu->addAction("Remove");
		qact_Info = contextMenu->addAction("Info");

		qact_Recovery->setIcon(UiResources::GetMe().icoRecovery());
		qact_Remove->setIcon(UiResources::GetMe().icoRemove());
		qact_Info->setIcon(UiResources::GetMe().icoHelp());

		connect(contextMenu, SIGNAL(triggered(QAction*)), this, SLOT(slotActivated(QAction*)));
	}

	const QMenu* Get() const {
		return contextMenu;
	}

	// Determines type of object and builds context menu
	void ShowMenu(QTreeWidgetItem* i)
	{
		qact_Recovery->setEnabled(true);
		qact_Remove->setEnabled(true);
		qact_Info->setEnabled(true);

		item = i;
		contextMenu->exec(QCursor::pos());
	}

signals:
	void signalRecovery(QTreeWidgetItem*);
	void signalDeleteFile(QTreeWidgetItem*);
	void signalInfo(QTreeWidgetItem*);

	public slots:
		void slotActivated(QAction* pAction) 
		{
			if(pAction == qact_Recovery)
				emit signalRecovery(item);
			else if(pAction == qact_Remove)
				emit signalDeleteFile(item);
			else if(pAction == qact_Info)
				emit signalInfo(item);
		}
};

#endif
