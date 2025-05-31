#include "mainwindow.h"
#include <QApplication>
#include <QFile>
#include <QTextStream>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QFile styleFile(":/stylesheet.qss");

    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        QTextStream stream(&styleFile);
        a.setStyleSheet(stream.readAll());
        styleFile.close();
        qDebug() << "Cтили загружены:" << styleFile.fileName();
    } else {
        qWarning() << "Ошибка при открытии стилей:" << styleFile.fileName() << "Error:" << styleFile.errorString();
    }

    QCoreApplication::setOrganizationName("Janvaar");
    QCoreApplication::setApplicationName("VirusTotalChecker");

    MainWindow w;
    qRegisterMetaType<ScanResult>("ScanResult"); 
    w.show();
    return a.exec();
}
