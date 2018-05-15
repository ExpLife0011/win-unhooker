
//	Author: 
//	burluckij@gmail.com
//	(c) Burlutsky Stanislav 2006 - 2014

#include "UiBuilder.h"

void Ui_ui_clientClass::InitMainPage()
{
	m_pageHome = new HomeWidget();
	m_Menu->addTab(m_pageHome, QString());
	m_Menu->setTabIcon(m_Menu->indexOf(m_pageHome), UiResources::GetMe().icoHome());
	m_Menu->setTabText(m_Menu->indexOf(m_pageHome), QObject::tr("Home"));
}

void Ui_ui_clientClass::InitScanPage()
{
	m_pageScan = new ScannerWidget();	
	m_Menu->addTab(m_pageScan, QString());
	m_Menu->setTabIcon(m_Menu->indexOf(m_pageScan), UiResources::GetMe().icoScan());
	m_Menu->setTabText(m_Menu->indexOf(m_pageScan), QObject::tr("Scanner"));
}

HomeWidget::HomeWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */):QWidget(parent, flags)
{
	m_startScan = new QPushButton(this);
	m_startScan->setText(QObject::tr("UMRD1: Memory scan"));
}

QuarantineWidget::QuarantineWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */):QWidget(parent, flags)
{
	QVBoxLayout* layout = new QVBoxLayout();
	QVBoxLayout* layout_GroupBoxContent = new QVBoxLayout();

	m_GroupBox = new QGroupBox(this);
	m_treeRemovedObjects = new ExtendedTree(m_GroupBox);

	layout_GroupBoxContent->addWidget(m_treeRemovedObjects);
	m_GroupBox->setLayout(layout_GroupBoxContent);
	layout->addWidget(m_GroupBox);
	this->setLayout(layout);

	m_treeRemovedObjects->setColumnCount(3);
	m_treeRemovedObjects->setColumnWidth(0, 190);
	m_treeRemovedObjects->setColumnWidth(1, 100);
	m_treeRemovedObjects->headerItem()->setText(0, QObject::tr("File"));
	m_treeRemovedObjects->headerItem()->setText(1, QObject::tr("Size"));
	m_treeRemovedObjects->headerItem()->setText(2, QObject::tr("Date"));
	m_treeRemovedObjects->headerItem()->setIcon(0, UiResources::GetMe().icoFolder());
	m_treeRemovedObjects->headerItem()->setIcon(1, UiResources::GetMe().icoInfo());
	m_treeRemovedObjects->headerItem()->setIcon(2, UiResources::GetMe().icoCalendar());

	m_GroupBox->setTitle(QObject::tr("Malware storage"));
}

ScannerWidget::ScannerWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */)
{
	QSize SizeForButtons(BUTTONS_SIZE);
	bool useFlatButtons = USE_FLAT_BUTTONS;

	QGridLayout* layout = new QGridLayout();
	QVBoxLayout* layout_GroupBox = new QVBoxLayout();
	QVBoxLayout* layout_Buttons = new QVBoxLayout();

	QHBoxLayout* l_time_elapsed = new QHBoxLayout();
	QHBoxLayout* l_scanned_objects = new QHBoxLayout();
	QHBoxLayout* l_found_objects = new QHBoxLayout();

	m_GroupBox = new QGroupBox(this);
	m_status = new QLabel(m_GroupBox);
	m_time_elapsed = new QLabel(m_GroupBox);
	m_scanned_objects = new QLabel(m_GroupBox);
	m_found_objects = new QLabel(m_GroupBox);
	m_progress = new QProgressBar(m_GroupBox);
	m_treeFoundObjects = new ExtendedTree(m_GroupBox);
	m_pause = new QPushButton(this);
	m_stop = new QPushButton(this);
	m_removeAll = new QPushButton(this);

	m_treeFoundObjects->setIconSize(QSize(16,16));
	m_pause->setIconSize(SizeForButtons);
	m_removeAll->setIconSize(SizeForButtons);
	m_stop->setIconSize(SizeForButtons);
	m_stop->setFlat(useFlatButtons);
	m_pause->setFlat(useFlatButtons);
	m_removeAll->setFlat(useFlatButtons);
	m_stop->setIcon(UiResources::GetMe().icoStop());
	m_pause->setIcon(UiResources::GetMe().icoPause());
	m_removeAll->setIcon(UiResources::GetMe().icoBin());

	m_GroupBox->setMouseTracking(false);
	m_GroupBox->setFlat(false);
	m_GroupBox->setCheckable(false);

	m_progress->setValue(0);
	m_progress->setTextVisible(false);
	m_progress->setTextDirection(QProgressBar::TopToBottom);

	QFont font;
	font.setFamily(QString::fromUtf8("Segoe UI"));
	m_status->setFont(font);

	m_treeFoundObjects->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	m_treeFoundObjects->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
	m_treeFoundObjects->setRootIsDecorated(true);
	m_treeFoundObjects->setUniformRowHeights(false);
	m_treeFoundObjects->setSortingEnabled(false);
	m_treeFoundObjects->setAnimated(false);
	m_treeFoundObjects->setAllColumnsShowFocus(false);
	m_treeFoundObjects->setWordWrap(false);
	m_treeFoundObjects->setHeaderHidden(true);
	m_treeFoundObjects->setColumnCount(1);
	m_treeFoundObjects->header()->setVisible(false);
	m_treeFoundObjects->header()->setCascadingSectionResizes(false);
	m_treeFoundObjects->header()->setHighlightSections(false);
	m_treeFoundObjects->header()->setProperty("showSortIndicator", QVariant(false));
	m_treeFoundObjects->header()->setStretchLastSection(true);

	l_time_elapsed->addWidget(m_time_elapsed);
	l_time_elapsed->addWidget(m_time_elapsed_n = new QLabel());
	l_time_elapsed->addStretch();

	l_found_objects->addWidget(m_found_objects);
	l_found_objects->addWidget(m_found_objects_n = new QLabel());
	l_found_objects->addStretch();

	l_scanned_objects->addWidget(m_scanned_objects);
	l_scanned_objects->addWidget(m_scanned_objects_n = new QLabel());
	l_scanned_objects->addStretch();

	layout_GroupBox->addLayout(l_time_elapsed);
	layout_GroupBox->addLayout(l_found_objects);
	layout_GroupBox->addLayout(l_scanned_objects);
	
	layout_GroupBox->addWidget(m_status);
	layout_GroupBox->addWidget(m_progress);
	layout_GroupBox->addWidget(m_treeFoundObjects);
	m_GroupBox->setLayout(layout_GroupBox);

	layout_Buttons->addWidget(m_pause);
	layout_Buttons->addWidget(m_stop);
	layout_Buttons->addStretch();
	layout_Buttons->addWidget(m_removeAll);

	layout->addWidget(m_GroupBox, 0, 0);
	layout->addLayout(layout_Buttons, 0, 1);

	this->setLayout(layout);

	m_GroupBox->setTitle(QObject::tr("Searching"));
	m_pause->setText(QObject::tr("Pause"));
	m_stop->setText(QObject::tr("Stop"));
	m_status->setText(QObject::tr("burluckij@gmail.com"));
	m_time_elapsed->setText(QObject::tr("Time elapsed: "));
	m_scanned_objects->setText(QObject::tr("Objects scanned: "));
	m_found_objects->setText(QObject::tr("Objects found: "));
	m_removeAll->setText(QObject::tr("Clean out"));

	m_treeFoundObjects->headerItem()->setHidden(FALSE);
	m_treeFoundObjects->headerItem()->setIcon(0, UiResources::GetMe().icoInfo());
	m_treeFoundObjects->headerItem()->setText(0, QObject::tr("Malware objects and suspicious activity"));
}

ProtectedLibsWidget::ProtectedLibsWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */):QWidget(parent, flags)
{
	QSize SizeForButtons(BUTTONS_SIZE);
	bool useFlatButtons = USE_FLAT_BUTTONS;
	QHBoxLayout* layoutProtectedTab = new QHBoxLayout();
	QHBoxLayout* layoutHTrustedLibs = new QHBoxLayout();
	QVBoxLayout* layout_GroupBox = new QVBoxLayout();
	QFont font1;
	font1.setBold(true);
	font1.setWeight(75);

	m_GroupBox = new QGroupBox(this);
	m_treeProtectedLibs = new ExtendedTree(m_GroupBox);
	m_libName = new QLineEdit(m_GroupBox);
	m_addLib = new QPushButton(m_GroupBox);
	m_removeAll = new QPushButton(m_GroupBox);
	m_addLib->setFlat(useFlatButtons);
	m_removeAll->setFlat(useFlatButtons);

	m_treeProtectedLibs->setIconSize(QSize(16,16));
	m_addLib->setIconSize(SizeForButtons);
	m_removeAll->setIconSize(SizeForButtons);
	m_addLib->setIcon(UiResources::GetMe().icoAdd());
	m_removeAll->setIcon(UiResources::GetMe().icoBin());
	m_libName->setFont(font1);
	m_libName->setMaxLength(250);

	layoutProtectedTab->addWidget(m_GroupBox); // push 1 == [1 0]

	layoutHTrustedLibs->addWidget(m_libName);
	layoutHTrustedLibs->addWidget(m_addLib);
	layoutHTrustedLibs->addWidget(m_removeAll);

	layout_GroupBox->addWidget(this->m_treeProtectedLibs);
	layout_GroupBox->addLayout(layoutHTrustedLibs);

	m_GroupBox->setLayout(layout_GroupBox);
	this->setLayout(layoutProtectedTab);

	m_treeProtectedLibs->headerItem()->setIcon(0, UiResources::GetMe().icoDll());

	m_removeAll->setText(QObject::tr("Clean out"));
	m_addLib->setText(QObject::tr("Add"));
	m_GroupBox->setTitle(QObject::tr("Protect imported functions from these libraries"));
	m_treeProtectedLibs->headerItem()->setText(0, QObject::tr("System and white objects"));
}

TrustedAppsWidget::TrustedAppsWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */):QWidget(parent, flags)
{
	QSize SizeForButtons(BUTTONS_SIZE);
	bool useFlatButtons = USE_FLAT_BUTTONS;
	QGroupBox	*gb_TrustedApps = new QGroupBox(this);
	QHBoxLayout* layout_TrustedApps = new QHBoxLayout();
	QHBoxLayout* layout_AddNewApp = new QHBoxLayout();
	QVBoxLayout* layout_GroupBox = new QVBoxLayout();
	QFont font1;
	font1.setBold(true);
	font1.setWeight(75);

	// Initializes UI components and builds hierarchy
	m_treeTrustedApps = new ExtendedTree(gb_TrustedApps);
	m_addApp = new QPushButton(gb_TrustedApps);
	m_removeAll = new QPushButton(gb_TrustedApps);

	m_treeTrustedApps->setIconSize(QSize(24,24));

	m_addApp->setFlat(useFlatButtons);
	m_removeAll->setFlat(useFlatButtons);
	m_removeAll->setIconSize(SizeForButtons);
	m_removeAll->setIcon(UiResources::GetMe().icoBin());
	m_addApp->setIconSize(SizeForButtons);
	m_addApp->setIcon(UiResources::GetMe().icoAdd());

	
	layout_TrustedApps->addWidget(gb_TrustedApps);
	layout_AddNewApp->addStretch();
	layout_AddNewApp->addWidget(this->m_addApp);
	layout_AddNewApp->addWidget(this->m_removeAll);

	layout_GroupBox->addWidget(m_treeTrustedApps);
	layout_GroupBox->addLayout(layout_AddNewApp);

	gb_TrustedApps->setLayout(layout_GroupBox);
	this->setLayout(layout_TrustedApps);

	
	m_addApp->setText(QObject::tr("Add"));
	m_removeAll->setText(QObject::tr("Clean out"));

	//m_treeTrustedApps->headerItem()->setIcon(0, UiResources::GetMe().icoCalendar());
	m_treeTrustedApps->headerItem()->setText(0, QObject::tr("Location"));
	gb_TrustedApps->setTitle(QObject::tr("These applications will be ignored during the scanning process"));
}

CommonSettingsWidget::CommonSettingsWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */):QWidget(parent, flags)
{
	QVBoxLayout* layout = new QVBoxLayout();
	QHBoxLayout* l_language = new QHBoxLayout();

	m_quarantine = new QCheckBox(this);
	m_heuristic	= new QCheckBox(this);
	m_protectLibs = new QCheckBox(this);
	m_language = new QLabel(this);
	m_language_select = new QComboBox(this);

	l_language->addWidget(m_language);
	l_language->addWidget(m_language_select);
	l_language->addStretch();

	layout->addLayout(l_language);
	layout->addWidget(m_quarantine);
	layout->addWidget(m_protectLibs);
	layout->addWidget(m_heuristic);
	layout->addStretch();

	this->setLayout(layout);

	m_language_select->addItem(UiResources::GetMe().icoRussian(), "Russian");
	m_language_select->addItem(UiResources::GetMe().icoEnglish(), "English");

	m_language->setText(QObject::tr("Language"));
	m_quarantine->setText(QObject::tr("Quarantine"));
	m_heuristic->setText(QObject::tr("Heuristic"));
	m_protectLibs->setText(QObject::tr("Protect only system Dlls"));
}

SettingsWidget::SettingsWidget(QWidget *parent /* = 0 */, Qt::WFlags flags /* = 0 */):QWidget(parent, flags)
{
	QVBoxLayout* layout_SubSettings = new QVBoxLayout();

	// Sub windows on options page
	m_SettingsSubWindows = new QTabWidget();
	m_SettingsSubWindows->setMouseTracking(false);
	m_SettingsSubWindows->setContextMenuPolicy(Qt::DefaultContextMenu);
	m_SettingsSubWindows->setLayoutDirection(Qt::LeftToRight);
	m_SettingsSubWindows->setAutoFillBackground(true); // false
	m_SettingsSubWindows->setTabPosition(QTabWidget::North); // QTabWidget::North
	m_SettingsSubWindows->setTabShape(QTabWidget::Rounded); // QTabWidget::Rounded
	m_SettingsSubWindows->setIconSize(QSize(24, 24));
	m_SettingsSubWindows->setElideMode(Qt::ElideNone);
	m_SettingsSubWindows->setUsesScrollButtons(true);
	m_SettingsSubWindows->setDocumentMode(true); // false
	m_SettingsSubWindows->setTabsClosable(false);
	m_SettingsSubWindows->setMovable(false);

	layout_SubSettings->addWidget(m_SettingsSubWindows);
	this->setLayout(layout_SubSettings);

	// 1. Common
	m_wgtWindowCommon = new CommonSettingsWidget();
	m_SettingsSubWindows->addTab(m_wgtWindowCommon, QString());

	m_SettingsSubWindows->setTabIcon(m_SettingsSubWindows->indexOf(m_wgtWindowCommon), UiResources::GetMe().icoSettings());
	m_SettingsSubWindows->setTabText(m_SettingsSubWindows->indexOf(m_wgtWindowCommon), QObject::tr("Common"));

	// 2. Protected libs
	m_wgtWindowProtectedLibs = new ProtectedLibsWidget();
	m_SettingsSubWindows->addTab(m_wgtWindowProtectedLibs, QString());

	m_SettingsSubWindows->setTabIcon(m_SettingsSubWindows->indexOf(m_wgtWindowProtectedLibs), UiResources::GetMe().icoDllBlack());
	m_SettingsSubWindows->setTabText(m_SettingsSubWindows->indexOf(m_wgtWindowProtectedLibs), QObject::tr("Protected libraries"));

	// 3. Trusted
	m_wgtWindowTrustedApps = new TrustedAppsWidget();
	m_SettingsSubWindows->addTab(m_wgtWindowTrustedApps, QString());

	m_SettingsSubWindows->setTabIcon(m_SettingsSubWindows->indexOf(m_wgtWindowTrustedApps), UiResources::GetMe().icoApplication());
	m_SettingsSubWindows->setTabText(m_SettingsSubWindows->indexOf(m_wgtWindowTrustedApps), QObject::tr("Trusted applications"));
}

void Ui_ui_clientClass::InitOptionsPage()
{
	// Creating 'Options' tab
	m_pageOptions = new SettingsWidget();
	m_Menu->addTab(m_pageOptions, QString());
	
	m_Menu->setTabIcon(m_Menu->indexOf(m_pageOptions), UiResources::GetMe().icoOptions());
	m_Menu->setTabText(m_Menu->indexOf(m_pageOptions), QObject::tr("Options"));
}

void Ui_ui_clientClass::InitQuarantinePage()
{
	m_pageQuarantine = new QuarantineWidget();
	m_Menu->addTab(m_pageQuarantine, QString());

	m_Menu->setTabIcon(m_Menu->indexOf(m_pageQuarantine), UiResources::GetMe().icoQuarantine());
	m_Menu->setTabText(m_Menu->indexOf(m_pageQuarantine), QObject::tr("Quarantine"));
}

void Ui_ui_clientClass::setupUi(QMainWindow *ui_clientClass)
{
	if (ui_clientClass->objectName().isEmpty())
		ui_clientClass->setObjectName(QString::fromUtf8("ui_clientClass"));

	ui_clientClass->setWindowModality(Qt::WindowModal);
	ui_clientClass->setEnabled(true);
	ui_clientClass->resize(600, 400);
	QSizePolicy sizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
	sizePolicy.setHorizontalStretch(0);
	sizePolicy.setVerticalStretch(0);
	sizePolicy.setHeightForWidth(ui_clientClass->sizePolicy().hasHeightForWidth());
	ui_clientClass->setSizePolicy(sizePolicy);
	ui_clientClass->setMouseTracking(true);
	ui_clientClass->setContextMenuPolicy(Qt::DefaultContextMenu);
	ui_clientClass->setAutoFillBackground(false);
	ui_clientClass->setStyleSheet(QString::fromUtf8(""));
	ui_clientClass->setInputMethodHints(Qt::ImhNone);
	ui_clientClass->setToolButtonStyle(Qt::ToolButtonFollowStyle);
	ui_clientClass->setAnimated(true);
	ui_clientClass->setTabShape(QTabWidget::Triangular);
	ui_clientClass->setDockNestingEnabled(false);
	ui_clientClass->setDockOptions(QMainWindow::AllowTabbedDocks|QMainWindow::AnimatedDocks);

	m_Menu = new QTabWidget(ui_clientClass);
	m_Menu->setMouseTracking(false);
	m_Menu->setContextMenuPolicy(Qt::DefaultContextMenu);
	m_Menu->setLayoutDirection(Qt::LeftToRight);
	m_Menu->setAutoFillBackground(false);
	m_Menu->setTabPosition(QTabWidget::North); // QTabWidget::North
	m_Menu->setTabShape(QTabWidget::Rounded); // QTabWidget::Rounded
	m_Menu->setIconSize(QSize(24, 24));
	m_Menu->setElideMode(Qt::ElideNone);
	m_Menu->setUsesScrollButtons(true);
	m_Menu->setDocumentMode(true); // false
	m_Menu->setTabsClosable(false);
	m_Menu->setMovable(true);

	InitMainPage();
	InitScanPage();
	InitOptionsPage();
	InitQuarantinePage();

	ui_clientClass->setCentralWidget(m_Menu);
	retranslateUi(ui_clientClass);
	m_Menu->setCurrentIndex(0);
	QMetaObject::connectSlotsByName(ui_clientClass);

} // setupUi
