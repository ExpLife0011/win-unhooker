
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	


#ifndef EX_DETECTED_ITEM_H
#define EX_DETECTED_ITEM_H

#include <QtGui/QMainWindow>
#include <QTreeWidget.h>
#include "images.h"
#include "RefObject.h"
#include "System.h"
#include "settings.h"

enum DescrFoundObject
{
	DEF_UNKNOWN,
	WIN_API_IMPORT_HOOK,
	SSDT_INTERCEPTOR,
	SYSER_INTERCEPTOR,
	HIDDEN_PROCESS,
	HIDDEN_DRIVER,
	HIDDEN_MODULE,
	HEURISTIC_SUSPICION
};

// this node has a relationship with detected object in scanner's list 
class DetectedItem : public QTreeWidgetItem
{
private:

	// it's mean a file on the disc (something physical)
	bool m_root;
	
	// 
	//INTERCEPTOR* m_objInfo;

	DescrFoundObject m_type;
	PVOID m_descriptionData;

	// Description by heuristic analyzer
	//PHEUR_FILE_DESCR m_heurDescription;

public: 
	bool Root() const {
		return m_root;
	}
	
	void Root(bool val) { 
		m_root = val;
	}

	void SetRed()
	{
		QColor color;
		color.setRed(150);
		this->setTextColor(0, color);
	}

	void SetGreen()
	{
		QColor color;
		color.setGreen(200);
		this->setTextColor(0, color);

	}

// 	INTERCEPTOR* ObjectInfo() const {
// 		return m_objInfo; 
// 	}

	DescrFoundObject GetType(){
		return m_type;
	}

// 	void ObjectInfo(const INTERCEPTOR* val) {
// 		m_objInfo = const_cast<INTERCEPTOR*>(val);
// 	}

	PVOID GetDescrData(){
		return m_descriptionData;
	}

	bool SaveDescrData(const void* p, ulong p_size)
	{
		PVOID p_copy = Memory::getmem(p_size);
		if (p_copy)
		{
			memcpy(p_copy, p, p_size);
			m_descriptionData = p_copy;
		}

		return p_copy != NULL;
	}

	DetectedItem(DescrFoundObject objtype = DEF_UNKNOWN, bool root_item = false):
	m_type(objtype), m_descriptionData(NULL), m_root(root_item)
	{
	};

	~DetectedItem(){

// 		if(m_objInfo)
// 			Memory::freemem(m_objInfo->pInfo);

		if(m_descriptionData)
		{
			Memory::freemem(m_descriptionData);
		}
	}
};

class TrustedAppItem : public QTreeWidgetItem
{

protected:
	PTRUSTED_APP m_appDescr;

public: 

	const PTRUSTED_APP AppDescription() const{
		return m_appDescr;
	}

	void AppDescription(PTRUSTED_APP pAppDescription){
		m_appDescr = pAppDescription;
	}

	TrustedAppItem(PTRUSTED_APP pDescr = NULL):m_appDescr(pDescr){
	}

	~TrustedAppItem(){
		// to free something
	}
};

#endif