
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#ifndef SYSTEM_DLLS_H
#define SYSTEM_DLLS_H

#include <QtGui/QMainWindow>
#include "images.h"
#include "ex_items.h"

class CntxMenuProtectedLib: public QWidget {
	Q_OBJECT

private:
	QMenu* contextMenu;
	QAction* qact0;
	QAction* qact1;

	QTreeWidgetItem* item_clicked;

	void BuildMenu(){
		contextMenu->exec(QCursor::pos());
	}

public:
	CntxMenuProtectedLib()
	{
		contextMenu = new QMenu(this);
		item_clicked = NULL;
		qact0 = contextMenu->addAction(QObject::tr("Rename"));
		qact1 = contextMenu->addAction(QObject::tr("Remove"));
		qact1->setIcon(UiResources::GetMe().icoRemove());
		qact0->setIcon(UiResources::GetMe().icoDll());

		connect(contextMenu, SIGNAL(triggered(QAction*)), this, SLOT(slotActivated(QAction*)));
	}

	void ShowMenu(QTreeWidgetItem* item)
	{
		item_clicked = item;
		qact0->setEnabled(false);
		this->BuildMenu();
	}

signals:
	void Remove(QTreeWidgetItem*, ulong);

	public slots:
		void slotActivated(QAction* pAction)
		{
			if(pAction == qact1)
				emit Remove(item_clicked, SYSLIB_ACTIVE);
		}
};

class CntxMenuTrustedApp: public QWidget {
	Q_OBJECT

private:
	QMenu* contextMenu;
	QAction* qactInfo;
	QAction* qactRemove;

	TrustedAppItem* pItem;

	void BuildMenu(){
		contextMenu->exec(QCursor::pos());
	}

public:
	CntxMenuTrustedApp():pItem(NULL)
	{
		contextMenu = new QMenu(this);
		qactInfo = contextMenu->addAction(QObject::tr("Info"));
		qactRemove = contextMenu->addAction("Remove");
		qactInfo->setIcon(UiResources::GetMe().icoInfo());
		qactRemove->setIcon(UiResources::GetMe().icoRemove());

		connect(contextMenu, SIGNAL(triggered(QAction*)), this, SLOT(slotActivated(QAction*)));
	}

	void ShowMenu(QTreeWidgetItem* item)
	{
		pItem = dynamic_cast<TrustedAppItem*>(item);
		this->BuildMenu();
	}

signals:
	void	Remove(QTreeWidgetItem*);
	void	Info(QTreeWidgetItem*);

public slots:
		void slotActivated(QAction* pAction)
		{
			if(pAction == qactInfo)
			{
				emit Info(pItem);
			}
			else if(pAction == qactRemove)
			{
				emit Remove(pItem);
			}
		}
};

/////////////////////////////////

// class CntxMenuTrustedApp: public QWidget {
// 	Q_OBJECT
// 
// private:
// 	QMenu* contextMenu;
// 	QAction* qact0;
// 	QAction* qact1;
// 
// 	TrustedAppItem* pItem;
// 
// 	void BuildMenu(){
// 		contextMenu->exec(QCursor::pos());
// 	}
// 
// public:
// 	CntxMenuTrustedApp():pItem(NULL)
// 	{
// 		contextMenu = new QMenu(this);
// 		qact0 = contextMenu->addAction("Info");
// 		qact1 = contextMenu->addAction(REMOVE_TXT);
// 		qact0->setIcon(UiResources::GetMe().icoInfo());
// 		qact1->setIcon(UiResources::GetMe().icoRemove());
// 
// 		connect(contextMenu, SIGNAL(triggered(QAction*)), this, SLOT(slotActivated(QAction*)));
// 	}
// 
// 	void ShowMenu(TrustedAppItem* item)
// 	{
// 		pItem = item;
// 		qact0->setEnabled(false);
// 		this->BuildMenu();
// 	}
// 
// signals:
// 	void	Remove(TrustedAppItem*, ulong);
// 	void	Info(TrustedAppItem* pItem);
// 
// 	public slots:
// 		void slotActivated(QAction* pAction)
// 		{
// 			// delete
// 			if(pAction == qact0)
// 			{
// 				emit Info(pItem);
// 			}
// 			else if(pAction == qact1)
// 			{
// 				emit Remove(pItem, SYSLIB_ACTIVE);
// 			}
// 		}
// };

#endif
