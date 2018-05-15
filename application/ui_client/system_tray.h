
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#ifndef SYSTEM_TRAY_H
#define SYSTEM_TRAY_H

#include <QtGui/QMainWindow>
#include "images.h"

class CM_Tray: public QWidget{
	Q_OBJECT

private:
	QMenu* m_contextMenu;
	QAction* m_qact0;
	QAction* m_qact1;

public:
	CM_Tray()
	{
		m_contextMenu = new QMenu(this);
		m_qact0 = m_contextMenu->addAction("Show");
		m_qact1 = m_contextMenu->addAction("Close");
		m_qact0->setIcon(UiResources::GetMe().icoHome());
		m_qact1->setIcon(UiResources::GetMe().icoClose());

		connect(m_contextMenu, SIGNAL(triggered(QAction*)), this, SLOT(slotActivated(QAction*)));
	}

	QMenu* Get()
	{
		return m_contextMenu;
	}

	void ShowMenu()
	{
		m_contextMenu->exec(QCursor::pos());
	}

signals:
	void signalShow();
	void signalExit();

	public slots:
		void slotActivated(QAction* pAction)
		{
			if(pAction == m_qact0)
				emit signalShow();
			else if(pAction == m_qact1)
				emit signalExit();
		}
};

#endif