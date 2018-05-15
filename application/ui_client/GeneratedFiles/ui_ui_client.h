/********************************************************************************
** Form generated from reading UI file 'ui_client.ui'
**
** Created: Sun 7. Sep 00:45:57 2014
**      by: Qt User Interface Compiler version 4.8.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_UI_CLIENT_H
#define UI_UI_CLIENT_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QCheckBox>
#include <QtGui/QGroupBox>
#include <QtGui/QHeaderView>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QMainWindow>
#include <QtGui/QProgressBar>
#include <QtGui/QPushButton>
#include <QtGui/QTabWidget>
#include <QtGui/QTreeWidget>
#include <QtGui/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ui_clientClass
{
public:
    QWidget *centralWidget;
    QTabWidget *Menu;
    QWidget *HOME_tab;
    QPushButton *scan1_btn;
    QWidget *SCAN_tab;
    QPushButton *pause_Button;
    QPushButton *stop_Button;
    QGroupBox *groupBox;
    QProgressBar *progressScan;
    QLabel *StatusString;
    QTreeWidget *treeScanLog;
    QPushButton *do_infect;
    QPushButton *clean_btn;
    QWidget *tab_Options;
    QGroupBox *groupBox_4;
    QCheckBox *checkBox_4;
    QCheckBox *chb_Syslib;
    QGroupBox *system_dlls;
    QTreeWidget *tree_syslib;
    QPushButton *btn_adddll;
    QLineEdit *line_dll;
    QWidget *tab_Quarantine;
    QGroupBox *groupBox_2;
    QTreeWidget *mtree;

    void setupUi(QMainWindow *ui_clientClass)
    {
        if (ui_clientClass->objectName().isEmpty())
            ui_clientClass->setObjectName(QString::fromUtf8("ui_clientClass"));
        ui_clientClass->setWindowModality(Qt::WindowModal);
        ui_clientClass->setEnabled(true);
        ui_clientClass->resize(536, 345);
        QSizePolicy sizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(ui_clientClass->sizePolicy().hasHeightForWidth());
        ui_clientClass->setSizePolicy(sizePolicy);
        ui_clientClass->setMinimumSize(QSize(525, 272));
        ui_clientClass->setMaximumSize(QSize(800, 800));
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
        centralWidget = new QWidget(ui_clientClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        Menu = new QTabWidget(centralWidget);
        Menu->setObjectName(QString::fromUtf8("Menu"));
        Menu->setGeometry(QRect(0, 0, 531, 341));
        Menu->setMinimumSize(QSize(521, 271));
        Menu->setMaximumSize(QSize(1500, 800));
        Menu->setMouseTracking(false);
        Menu->setContextMenuPolicy(Qt::DefaultContextMenu);
        Menu->setLayoutDirection(Qt::LeftToRight);
        Menu->setAutoFillBackground(false);
        Menu->setTabPosition(QTabWidget::North);
        Menu->setTabShape(QTabWidget::Rounded);
        Menu->setIconSize(QSize(24, 24));
        Menu->setElideMode(Qt::ElideNone);
        Menu->setUsesScrollButtons(true);
        Menu->setDocumentMode(false);
        Menu->setTabsClosable(false);
        Menu->setMovable(true);
        HOME_tab = new QWidget();
        HOME_tab->setObjectName(QString::fromUtf8("HOME_tab"));
        scan1_btn = new QPushButton(HOME_tab);
        scan1_btn->setObjectName(QString::fromUtf8("scan1_btn"));
        scan1_btn->setGeometry(QRect(4, 20, 151, 41));
        Menu->addTab(HOME_tab, QString());
        SCAN_tab = new QWidget();
        SCAN_tab->setObjectName(QString::fromUtf8("SCAN_tab"));
        pause_Button = new QPushButton(SCAN_tab);
        pause_Button->setObjectName(QString::fromUtf8("pause_Button"));
        pause_Button->setGeometry(QRect(449, 6, 71, 23));
        stop_Button = new QPushButton(SCAN_tab);
        stop_Button->setObjectName(QString::fromUtf8("stop_Button"));
        stop_Button->setGeometry(QRect(449, 36, 71, 23));
        stop_Button->setIconSize(QSize(16, 16));
        stop_Button->setCheckable(false);
        stop_Button->setChecked(false);
        stop_Button->setDefault(false);
        stop_Button->setFlat(false);
        groupBox = new QGroupBox(SCAN_tab);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        groupBox->setGeometry(QRect(0, 0, 441, 301));
        groupBox->setMouseTracking(false);
        groupBox->setFlat(false);
        groupBox->setCheckable(false);
        progressScan = new QProgressBar(groupBox);
        progressScan->setObjectName(QString::fromUtf8("progressScan"));
        progressScan->setGeometry(QRect(10, 50, 421, 23));
        progressScan->setValue(0);
        progressScan->setTextVisible(false);
        progressScan->setTextDirection(QProgressBar::TopToBottom);
        StatusString = new QLabel(groupBox);
        StatusString->setObjectName(QString::fromUtf8("StatusString"));
        StatusString->setGeometry(QRect(10, 19, 521, 21));
        QFont font;
        font.setFamily(QString::fromUtf8("Segoe UI"));
        StatusString->setFont(font);
        treeScanLog = new QTreeWidget(groupBox);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeScanLog->setHeaderItem(__qtreewidgetitem);
        treeScanLog->setObjectName(QString::fromUtf8("treeScanLog"));
        treeScanLog->setGeometry(QRect(10, 80, 421, 211));
        treeScanLog->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        treeScanLog->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        treeScanLog->setRootIsDecorated(true);
        treeScanLog->setUniformRowHeights(false);
        treeScanLog->setSortingEnabled(false);
        treeScanLog->setAnimated(false);
        treeScanLog->setAllColumnsShowFocus(false);
        treeScanLog->setWordWrap(false);
        treeScanLog->setHeaderHidden(true);
        treeScanLog->setColumnCount(1);
        treeScanLog->header()->setVisible(false);
        treeScanLog->header()->setCascadingSectionResizes(false);
        treeScanLog->header()->setHighlightSections(false);
        treeScanLog->header()->setProperty("showSortIndicator", QVariant(false));
        treeScanLog->header()->setStretchLastSection(true);
        do_infect = new QPushButton(SCAN_tab);
        do_infect->setObjectName(QString::fromUtf8("do_infect"));
        do_infect->setGeometry(QRect(450, 278, 71, 23));
        clean_btn = new QPushButton(SCAN_tab);
        clean_btn->setObjectName(QString::fromUtf8("clean_btn"));
        clean_btn->setGeometry(QRect(450, 251, 71, 23));
        Menu->addTab(SCAN_tab, QString());
        tab_Options = new QWidget();
        tab_Options->setObjectName(QString::fromUtf8("tab_Options"));
        groupBox_4 = new QGroupBox(tab_Options);
        groupBox_4->setObjectName(QString::fromUtf8("groupBox_4"));
        groupBox_4->setGeometry(QRect(350, -1, 171, 301));
        checkBox_4 = new QCheckBox(groupBox_4);
        checkBox_4->setObjectName(QString::fromUtf8("checkBox_4"));
        checkBox_4->setGeometry(QRect(8, 20, 281, 18));
        chb_Syslib = new QCheckBox(groupBox_4);
        chb_Syslib->setObjectName(QString::fromUtf8("chb_Syslib"));
        chb_Syslib->setGeometry(QRect(8, 40, 281, 18));
        chb_Syslib->setChecked(true);
        system_dlls = new QGroupBox(tab_Options);
        system_dlls->setObjectName(QString::fromUtf8("system_dlls"));
        system_dlls->setGeometry(QRect(3, -1, 341, 301));
        tree_syslib = new QTreeWidget(system_dlls);
        tree_syslib->setObjectName(QString::fromUtf8("tree_syslib"));
        tree_syslib->setGeometry(QRect(4, 15, 331, 251));
        btn_adddll = new QPushButton(system_dlls);
        btn_adddll->setObjectName(QString::fromUtf8("btn_adddll"));
        btn_adddll->setGeometry(QRect(284, 274, 51, 21));
        btn_adddll->setIconSize(QSize(32, 32));
        line_dll = new QLineEdit(system_dlls);
        line_dll->setObjectName(QString::fromUtf8("line_dll"));
        line_dll->setGeometry(QRect(4, 275, 271, 20));
        QFont font1;
        font1.setBold(true);
        font1.setWeight(75);
        line_dll->setFont(font1);
        line_dll->setMaxLength(250);
        Menu->addTab(tab_Options, QString());
        tab_Quarantine = new QWidget();
        tab_Quarantine->setObjectName(QString::fromUtf8("tab_Quarantine"));
        groupBox_2 = new QGroupBox(tab_Quarantine);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        groupBox_2->setGeometry(QRect(2, -1, 511, 291));
        mtree = new QTreeWidget(groupBox_2);
        QTreeWidgetItem *__qtreewidgetitem1 = new QTreeWidgetItem();
        __qtreewidgetitem1->setText(0, QString::fromUtf8("File"));
        mtree->setHeaderItem(__qtreewidgetitem1);
        mtree->setObjectName(QString::fromUtf8("mtree"));
        mtree->setGeometry(QRect(10, 20, 491, 261));
        Menu->addTab(tab_Quarantine, QString());
        ui_clientClass->setCentralWidget(centralWidget);

        retranslateUi(ui_clientClass);

        Menu->setCurrentIndex(0);


        QMetaObject::connectSlotsByName(ui_clientClass);
    } // setupUi

    void retranslateUi(QMainWindow *ui_clientClass)
    {
        ui_clientClass->setWindowTitle(QApplication::translate("ui_clientClass", "User Mode Security", 0, QApplication::UnicodeUTF8));
#ifndef QT_NO_TOOLTIP
        ui_clientClass->setToolTip(QString());
#endif // QT_NO_TOOLTIP
        scan1_btn->setText(QApplication::translate("ui_clientClass", "UMRD1: Memory scan", 0, QApplication::UnicodeUTF8));
        Menu->setTabText(Menu->indexOf(HOME_tab), QApplication::translate("ui_clientClass", "Home", 0, QApplication::UnicodeUTF8));
        pause_Button->setText(QApplication::translate("ui_clientClass", "Pause", 0, QApplication::UnicodeUTF8));
        stop_Button->setText(QApplication::translate("ui_clientClass", "Stop  ", 0, QApplication::UnicodeUTF8));
        groupBox->setTitle(QApplication::translate("ui_clientClass", "Search", 0, QApplication::UnicodeUTF8));
        StatusString->setText(QApplication::translate("ui_clientClass", "burluckij@gmail.com", 0, QApplication::UnicodeUTF8));
        do_infect->setText(QApplication::translate("ui_clientClass", "Remove", 0, QApplication::UnicodeUTF8));
        clean_btn->setText(QApplication::translate("ui_clientClass", "Clean", 0, QApplication::UnicodeUTF8));
        Menu->setTabText(Menu->indexOf(SCAN_tab), QApplication::translate("ui_clientClass", "Scaner", 0, QApplication::UnicodeUTF8));
        groupBox_4->setTitle(QApplication::translate("ui_clientClass", "Common", 0, QApplication::UnicodeUTF8));
        checkBox_4->setText(QApplication::translate("ui_clientClass", "On Quarantine", 0, QApplication::UnicodeUTF8));
        chb_Syslib->setText(QApplication::translate("ui_clientClass", "Search only system api hooks", 0, QApplication::UnicodeUTF8));
        system_dlls->setTitle(QApplication::translate("ui_clientClass", "System dll's", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem = tree_syslib->headerItem();
        ___qtreewidgetitem->setText(0, QApplication::translate("ui_clientClass", "System & white objects", 0, QApplication::UnicodeUTF8));
        btn_adddll->setText(QApplication::translate("ui_clientClass", "Add", 0, QApplication::UnicodeUTF8));
        Menu->setTabText(Menu->indexOf(tab_Options), QApplication::translate("ui_clientClass", "Options", 0, QApplication::UnicodeUTF8));
        groupBox_2->setTitle(QApplication::translate("ui_clientClass", "Malware storge", 0, QApplication::UnicodeUTF8));
        QTreeWidgetItem *___qtreewidgetitem1 = mtree->headerItem();
        ___qtreewidgetitem1->setText(1, QApplication::translate("ui_clientClass", "Info", 0, QApplication::UnicodeUTF8));
        Menu->setTabText(Menu->indexOf(tab_Quarantine), QApplication::translate("ui_clientClass", "Quarantine", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class ui_clientClass: public Ui_ui_clientClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_UI_CLIENT_H
