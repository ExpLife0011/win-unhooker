
//      (c)VsoftLab 2006 - 2013
//		Author: burluckij@gmail.com	

#include <QtGui/QApplication>
#include <QTextCodec.h>
#include <QTranslator.h>
#include "Window.h"
#include "ui_objects.h"
#include <vector>
#include "quarantine.h"
#include "client0.h"

void test_client0()
{
	client0* pclient = &client0::GetClient("G:\\CyberPeace\\client0\\Win7Debug\\client0.sys", "client0_test");

	bool installed = client0::InstallAndLoad(*pclient);

	if(installed == FALSE){
		MessageBoxA(0, "client wasn't installed", "test_client0", 0);
	}

	MessageBoxA(0, "Press OK to unload and delete client0 driver", "test_client0", MB_YESNO);

	if(pclient->UnloadDriver())
	{
		if(pclient->DeleteService() == FALSE)
		{
			MessageBoxA(0, "client0 wasn't deleted", "test_client0", MB_YESNO);
		}
		
	} else {
		MessageBoxA(0, "client0 wasn't unloaded", "test_client0", MB_YESNO);
	}

	delete pclient;
}

int main(int argc, char *argv[])
{
	DWORD dwTemp;
	QApplication a(argc, argv);

	// Load localization's file
	QTranslator* ptranslator = new QTranslator(0);
	bool b = ptranslator->load("uibuilder_en.qm", ".");
	if (b == false)
	{
		MessageBoxA(0,"error load translations", "tr", 0);
	}
	
	a.installTranslator(ptranslator);

	Q_INIT_RESOURCE(ui_client);
	QTextCodec* codec = QTextCodec::codecForName("Windows-1251");
	QTextCodec::setCodecForCStrings(codec);
	QApplication::addLibraryPath(QApplication::applicationDirPath() + QLatin1String("/Plugins"));
	QApplication::addLibraryPath(QLatin1String("g:\\CyberPeace\\plugins"));

	
	ui_client w;
	w.show();

	a.setWindowIcon( QIcon(APP_ICO));

	System::GetMaxPriv();
	//Quarantine  d("g:\\ui_client\\killed");
	//d.loadFrom();
	//bool f = d.DeleteObject("g:\\ui_client\\killed\\file1.txt");

	// оставим приложение висеть постоянно в трее
	//QApplication::setQuitOnLastWindowClosed(false);
	
	LoadLibraryA("G:\\CyberPeace\\rootkit_lib.dll");
	LoadLibraryA("rootkit_lib.dll");

// 	ULONG n = 0xFF;
// 	QString str = QString("data is %1").arg(n, 0, 16);
// 
// 	MessageBox(0, str.toAscii().constData(), "d", 0);
// 	return 0;

	//test_client0();
	return a.exec();
}