#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSqlDatabase>
#include <QJsonObject>
#include <QThread>
#include <QMetaType>

// Forward-декларация для UI класса
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

struct ScanResult {
    QString filePath;
    QString fileName;
    qint64 fileSize;
    QString hashMD5;
    QString scanTime;     // Время последнего сканирования VT
    QString vtResult;
    QString scanId;       // ID для получения отчета, если файл только что загружен
    QString status;       // "Pending", "Scanning", "Completed", "Error", "From DB"
    QString rawVtResponse; // Полный JSON ответ от VT

    bool isFromDb = false; // результат загружен из БД
    bool needsScan = true; // нужно ли сканировать (если нет в БД или пользователь хочет перескан)
};


class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButtonAddFiles_clicked();
    void on_pushButtonScanSelected_clicked();
    void on_pushButtonSearch_clicked();
    void on_pushButtonClearSearch_clicked();
    void on_pushButtonSetApiKey_clicked();

    // Слот для обновления GUI из потока
    void updateTableWithScanResult(const ScanResult& result, int row);


private:
    Ui::MainWindow *ui;
    QStandardItemModel *m_model; // Модель для таблицы
    QNetworkAccessManager *m_networkManager;
    QSqlDatabase m_db;
    QString m_apiKey;

    enum TableColumns {
        COL_NAME,
        COL_SIZE,
        COL_HASH,
        COL_SCAN_TIME,
        COL_VT_RESULT,
        COL_STATUS,
        COL_COUNT
    };

    void setupDatabase();
    void loadApiKey();
    void saveApiKey(const QString &key);
    void setupTableView();
    void loadResultsFromDb(const QString &searchTerm = "");
    QString calculateMD5(const QString &filePath);

    void addFileToTableModel(const ScanResult &fileInfo, bool isNew);
    int findRowByHash(const QString &hash);

    // методы для работы с VirusTotal API (будут выполняться в потоках)
    void performScanTask(QString filePath, QString fileHash, int row);
    void requestFileReport(const QString &resourceHash, int row);
    void uploadFileForScan(const QString &filePath, const QString &fileHash, int row);

    // для управления потоками
    std::vector<std::thread> m_scanThreads;

signals:
    // Сигнал для безопасного обновления UI из другого потока
    void scanResultReady(const ScanResult& result, int row);
};
#endif // MAINWINDOW_H
