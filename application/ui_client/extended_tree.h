
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#ifndef EXTENDED_TREE_H
#define EXTENDED_TREE_H

#include <QTreeWidget.h>
#include "images.h"

class ExtendedTree: public QTreeWidget
{
	Q_OBJECT

private:
	bool rightButtonClicked;

public:
	ExtendedTree(QWidget * parent = 0):rightButtonClicked(FALSE), QTreeWidget(parent){}

	bool RightButtonClicked(){
		return rightButtonClicked;
	}

protected:
	virtual void mousePressEvent(QMouseEvent* event){
		rightButtonClicked = (event->button() == Qt::RightButton);
		QTreeWidget::mousePressEvent(event);
	}
};

#endif