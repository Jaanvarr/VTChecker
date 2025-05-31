#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QSettings>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSqlError>
#include <QSqlQuery>
#include <QDateTime>
#include <QHttpMultiPart>
#include <QUrlQuery>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_networkManager(new QNetworkAccessManager(this))
{
    ui->setupUi(this);
    this->setWindowTitle("VirusTotal File Checker");

    qRegisterMetaType<ScanResult>("ScanResult");

    loadApiKey();
    setupDatabase();
    setupTableView();
    loadResultsFromDb();

    // Соединяем сигнал для обновления UI из потока со слотом
    connect(this, &MainWindow::scanResultReady, this, &MainWindow::updateTableWithScanResult, Qt::QueuedConnection);
}

MainWindow::~MainWindow()
{
    if (m_db.isOpen()) {
        m_db.close();
    }
    delete ui;
}

// Управление API ключом
void MainWindow::loadApiKey() {
    QSettings settings("Jaanvarr", "VirusTotalChecker");
    m_apiKey = settings.value("apiKey").toString();
    if (m_apiKey.isEmpty()) {
        ui->labelApiKeyStatus->setText("Ключ не установлен.");
        ui->lineEditApiKey->setPlaceholderText("Введите API ключ");
    } else {
        ui->lineEditApiKey->setText(m_apiKey);
        ui->labelApiKeyStatus->setText("Key setted.");
    }
}

void MainWindow::saveApiKey(const QString &key) {
    QSettings settings("Jaanvarr", "VirusTotalChecker");
    settings.setValue("apiKey", key);
    m_apiKey = key;
    ui->labelApiKeyStatus->setText("Ключ сохранен.");
    QMessageBox::information(this, "API ключ", "API ключ сохранен.");
}

void MainWindow::on_pushButtonSetApiKey_clicked() {
    QString key = ui->lineEditApiKey->text().trimmed();
    if (key.isEmpty()) {
        QMessageBox::warning(this, "API ключ", "API ключ пустой.");
        return;
    }
    saveApiKey(key);
}


// БД и таблица
void MainWindow::setupDatabase() {
    m_db = QSqlDatabase::addDatabase("QSQLITE");
    QString dbPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(dbPath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    m_db.setDatabaseName(dbPath + "/virustotal_cache.sqlite");

    if (!m_db.open()) {
        QMessageBox::critical(this, "BD error", "Cant open/create BD: " + m_db.lastError().text());
        return;
    }

    QSqlQuery query(m_db);
    QString createTableQuery = R"(
        CREATE TABLE IF NOT EXISTS scan_results (
            hash_md5 TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            scan_time TEXT,
            vt_result TEXT,
            raw_vt_response TEXT
        );
    )";
    if (!query.exec(createTableQuery)) {
        QMessageBox::critical(this, "BD Error", "Can't create BD: " + query.lastError().text());
    }
}

void MainWindow::setupTableView() {
    m_model = new QStandardItemModel(0, TableColumns::COL_COUNT, this); // 0 строк, N столбцов
    m_model->setHorizontalHeaderLabels({
        "Имя файла", "Размер", "MD5 Хэш", "Время проверки (VT)", "Результат VT", "Статус"
    });
    ui->tableViewResults->setModel(m_model);
    ui->tableViewResults->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableViewResults->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableViewResults->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tableViewResults->horizontalHeader()->setSectionResizeMode(COL_SIZE, QHeaderView::ResizeToContents);
    ui->tableViewResults->horizontalHeader()->setSectionResizeMode(COL_VT_RESULT, QHeaderView::ResizeToContents);
    ui->tableViewResults->horizontalHeader()->setSectionResizeMode(COL_STATUS, QHeaderView::ResizeToContents);
}

// Загрузка/Добавление данных в таблицу
void MainWindow::loadResultsFromDb(const QString &searchTerm) {
    m_model->removeRows(0, m_model->rowCount()); // Очистить таблицу перед загрузкой

    QSqlQuery query(m_db);
    QString queryString = "SELECT hash_md5, file_name, file_size, scan_time, vt_result, raw_vt_response FROM scan_results";
    if (!searchTerm.isEmpty()) {
        queryString += " WHERE file_name LIKE :term OR hash_md5 LIKE :term";
    }

    query.prepare(queryString);
    if (!searchTerm.isEmpty()) {
        query.bindValue(":term", "%" + searchTerm + "%");
    }

    if (!query.exec()) {
        qWarning() << "Ошибка загрузки из БД:" << query.lastError().text();
        return;
    }

    while (query.next()) {
        ScanResult result;
        result.hashMD5 = query.value("hash_md5").toString();
        result.fileName = query.value("file_name").toString();
        result.fileSize = query.value("file_size").toLongLong();
        result.scanTime = query.value("scan_time").toString();
        result.vtResult = query.value("vt_result").toString();
        result.rawVtResponse = query.value("raw_vt_response").toString();
        result.status = "Из БД";
        result.isFromDb = true;
        result.needsScan = false; // не сканируем то, что из БД
        addFileToTableModel(result, false);
    }
}

void MainWindow::addFileToTableModel(const ScanResult &fileInfo, bool isNewEntry) {
    // нет ли уже файла с таким хешем в таблице
    if (isNewEntry) {
        for (int i = 0; i < m_model->rowCount(); ++i) {
            if (m_model->item(i, COL_HASH)->text() == fileInfo.hashMD5) {
                QMessageBox::information(this, "Файл уже в списке",
                                         "Файл " + fileInfo.fileName + " (хэш: " + fileInfo.hashMD5 + ") уже есть в списке.");
                return;
            }
        }
    }

    QList<QStandardItem *> rowItems;
    rowItems << new QStandardItem(fileInfo.fileName);
    rowItems << new QStandardItem(QString::number(fileInfo.fileSize) + " B");
    rowItems << new QStandardItem(fileInfo.hashMD5);
    rowItems << new QStandardItem(fileInfo.scanTime);
    rowItems << new QStandardItem(fileInfo.vtResult);
    rowItems << new QStandardItem(fileInfo.status);

    // сохраняем полный путь и другие данные в UserRole первого элемента (имя файла)
    QVariantMap itemData;
    itemData["filePath"] = fileInfo.filePath;
    itemData["hashMD5"] = fileInfo.hashMD5;
    itemData["isFromDb"] = fileInfo.isFromDb;
    itemData["needsScan"] = fileInfo.needsScan; // true для новых файлов
    itemData["status"] = fileInfo.status;
    rowItems[COL_NAME]->setData(itemData, Qt::UserRole);

    m_model->appendRow(rowItems);
}

int MainWindow::findRowByHash(const QString &hash) {
    for (int i = 0; i < m_model->rowCount(); ++i) {
        QStandardItem *hashItem = m_model->item(i, COL_HASH);
        if (hashItem && hashItem->text() == hash) {
            return i;
        }
    }
    return -1;
}

// Обработчики кнопок
void MainWindow::on_pushButtonAddFiles_clicked() {
    QStringList filePaths = QFileDialog::getOpenFileNames(this, "Выбрать файлы для проверки", QDir::homePath());
    if (filePaths.isEmpty()) {
        return;
    }

    for (const QString &filePath : filePaths) {
        QFileInfo fileInfo(filePath);
        if (!fileInfo.exists() || !fileInfo.isFile()) continue;

        ScanResult sr;
        sr.filePath = filePath;
        sr.fileName = fileInfo.fileName();
        sr.fileSize = fileInfo.size();
        sr.hashMD5 = calculateMD5(filePath);
        sr.status = "Ожидание";
        sr.needsScan = true; // Новый файл, нужно сканировать

        // Проверить, есть ли уже в БД
        QSqlQuery query(m_db);
        query.prepare("SELECT scan_time, vt_result, raw_vt_response FROM scan_results WHERE hash_md5 = :hash");
        query.bindValue(":hash", sr.hashMD5);
        if (query.exec() && query.next()) {
            sr.scanTime = query.value("scan_time").toString();
            sr.vtResult = query.value("vt_result").toString();
            sr.rawVtResponse = query.value("raw_vt_response").toString();
            sr.status = "Из БД (Локально)";
            sr.isFromDb = true;
            sr.needsScan = false; // не сканируем, если есть в БД
        }
        addFileToTableModel(sr, true);
    }
}

void MainWindow::on_pushButtonScanSelected_clicked() {
    if (m_apiKey.isEmpty()) {
        QMessageBox::warning(this, "Нет API ключа", "Пожалуйста, введите и сохраните API ключ VirusTotal.");
        return;
    }

    QModelIndexList selectedRows = ui->tableViewResults->selectionModel()->selectedRows();
    if (selectedRows.isEmpty()) {
        QMessageBox::information(this, "Сканирование", "Выберите файлы для сканирования из таблицы.");
        return;
    }

    int scansInitiated = 0;
    for (const QModelIndex &index : selectedRows) {
        int row = index.row();
        QStandardItem *nameItem = m_model->item(row, COL_NAME);
        QVariantMap itemData = nameItem->data(Qt::UserRole).toMap();

        // проверяем, нужно ли сканировать этот файл (новый или пользователь хочет пересканировать)

        QString currentStatus = m_model->item(row, COL_STATUS)->text();
        if (currentStatus == "Сканирование...") {
            continue;
        }

        QString filePath = itemData["filePath"].toString();
        QString fileHash = itemData["hashMD5"].toString();

        if (fileHash.isEmpty()) {
            qWarning() << "Хэш для файла" << nameItem->text() << "не найден в данных элемента.";
            continue;
        }

        m_model->item(row, COL_STATUS)->setText("Запрос отчета...");

        // Создаем и отсоединяем поток

        std::thread scanThread(&MainWindow::performScanTask, this, filePath, fileHash, row);
        scanThread.detach();
        // m_scanThreads.push_back(std::move(scanThread)); // todo управление потоками
        scansInitiated++;
    }
    if(scansInitiated > 0) {
        statusBar()->showMessage(QString("Запущено сканирований: %1. Ожидайте результатов.").arg(scansInitiated), 5000);
    } else {
        statusBar()->showMessage("Не выбрано файлов для нового сканирования или они уже сканируются.", 3000);
    }
}

void MainWindow::on_pushButtonSearch_clicked() {
    QString searchTerm = ui->lineEditSearch->text().trimmed();
    loadResultsFromDb(searchTerm);
    if (m_model->rowCount() == 0 && !searchTerm.isEmpty()) {
        statusBar()->showMessage("По вашему запросу ничего не найдено в локальной БД.", 3000);
    } else if (m_model->rowCount() > 0 && !searchTerm.isEmpty()){
        statusBar()->showMessage(QString("Найдено %1 записей.").arg(m_model->rowCount()), 3000);
    }
}

void MainWindow::on_pushButtonClearSearch_clicked() {
    ui->lineEditSearch->clear();
    loadResultsFromDb(); // загрузить все
    statusBar()->showMessage("Поиск сброшен. Отображены все записи из БД.", 3000);
}


// Хэш MD5
QString MainWindow::calculateMD5(const QString &filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Не удалось открыть файл для расчета MD5:" << filePath;
        return QString();
    }
    QCryptographicHash hash(QCryptographicHash::Md5);
    if (file.size() > 1024 * 1024 * 50) { // Если файл большой, читаем по частям
        char buffer[8192];
        qint64 bytesRead;
        while ((bytesRead = file.read(buffer, sizeof(buffer))) > 0) {
            hash.addData(buffer, bytesRead);
        }
    } else {
        hash.addData(file.readAll());
    }
    file.close();
    return QString(hash.result().toHex());
}

// Логика VirusTotal API

void MainWindow::performScanTask(QString filePath, QString fileHash, int row) {
    QNetworkAccessManager localNam; // Локальный менеджер для этого потока
    QEventLoop loop; 

    // Запрос отчета по хэшу
    QNetworkRequest reportRequest(QUrl("https://www.virustotal.com/vtapi/v2/file/report"));
    QUrlQuery query;
    query.addQueryItem("apikey", m_apiKey); // m_apiKey должен быть доступен
    query.addQueryItem("resource", fileHash);
    reportRequest.setUrl(QUrl("https://www.virustotal.com/vtapi/v2/file/report?" + query.toString(QUrl::FullyEncoded)));
    reportRequest.setRawHeader("Accept", "application/json");

    qDebug() << "Thread" << QThread::currentThreadId() << ": Requesting report for hash" << fileHash;
    QNetworkReply *reportReply = localNam.get(reportRequest);
    connect(reportReply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec(); // Блокирует до получения ответа

    ScanResult scanData; // Структура для передачи данных в главный поток
    scanData.hashMD5 = fileHash;
    scanData.filePath = filePath; // Для случая, если нужно будет загружать
    QFileInfo fi(filePath);
    scanData.fileName = fi.fileName();
    scanData.fileSize = fi.size();


    if (reportReply->error() == QNetworkReply::NoError) {
        QByteArray responseData = reportReply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(responseData);
        QJsonObject jsonObj = jsonDoc.object();
        qDebug() << "Thread" << QThread::currentThreadId() << ": Report JSON:" << jsonObj;

        int responseCode = jsonObj.value("response_code").toInt(-1); // -1 если не найдено
        scanData.rawVtResponse = QString::fromUtf8(responseData);

        if (responseCode == 1) {
            scanData.scanTime = jsonObj.value("scan_date").toString();
            int positives = jsonObj.value("positives").toInt(0);
            int total = jsonObj.value("total").toInt(0);
            scanData.vtResult = QString("%1/%2").arg(positives).arg(total);
            scanData.status = "Завершено (Отчет)";
            scanData.needsScan = false;

            // todo через сигнал в главный поток
            QSqlQuery dbQuery(m_db);
            dbQuery.prepare("REPLACE INTO scan_results (hash_md5, file_name, file_size, scan_time, vt_result, raw_vt_response) "
                            "VALUES (:hash, :name, :size, :time, :result, :raw)");
            dbQuery.bindValue(":hash", scanData.hashMD5);
            dbQuery.bindValue(":name", scanData.fileName);
            dbQuery.bindValue(":size", scanData.fileSize);
            dbQuery.bindValue(":time", scanData.scanTime);
            dbQuery.bindValue(":result", scanData.vtResult);
            dbQuery.bindValue(":raw", scanData.rawVtResponse);
            if (!dbQuery.exec()) {
                qWarning() << "Thread" << QThread::currentThreadId() << "DB Error on replace (report):" << dbQuery.lastError().text();
            }

            emit scanResultReady(scanData, row); // Отправляем сигнал в главный поток
        } else if (responseCode == 0) { // Файл неизвестен, нужно загружать
            qDebug() << "Thread" << QThread::currentThreadId() << ": File unknown, attempting upload:" << filePath;
            if (filePath.isEmpty() || !QFile::exists(filePath)) {
                scanData.status = "Ошибка: Файл не найден для загрузки";
                scanData.vtResult = "N/A";
                emit scanResultReady(scanData, row);
                reportReply->deleteLater();
                return;
            }

            // 2. Загрузка файла (если filePath передан и файл существует)
            QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

            QHttpPart apiKeyPart;
            apiKeyPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"apikey\""));
            apiKeyPart.setBody(m_apiKey.toUtf8());
            multiPart->append(apiKeyPart);

            QHttpPart filePart;
            filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file\"; filename=\"" + QFileInfo(filePath).fileName() + "\""));
            QFile *file = new QFile(filePath);
            if (!file->open(QIODevice::ReadOnly)) {
                qWarning() << "Thread" << QThread::currentThreadId() << "Cannot open file for upload:" << filePath;
                scanData.status = "Ошибка: Не удалось открыть файл";
                emit scanResultReady(scanData, row);
                delete file;
                multiPart->deleteLater(); // Важно очистить multipart
                reportReply->deleteLater();
                return;
            }
            filePart.setBodyDevice(file);
            file->setParent(multiPart); // multiPart станет владельцем файла
            multiPart->append(filePart);

            QNetworkRequest uploadRequest(QUrl("https://www.virustotal.com/vtapi/v2/file/scan"));
            QNetworkReply *uploadReply = localNam.post(uploadRequest, multiPart);
            multiPart->setParent(uploadReply); // uploadReply станет владельцем multiPart

            connect(uploadReply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
            loop.exec(); // Блокируем до получения ответа на загрузку

            if (uploadReply->error() == QNetworkReply::NoError) {
                QByteArray uploadResponseData = uploadReply->readAll();
                QJsonDocument uploadJsonDoc = QJsonDocument::fromJson(uploadResponseData);
                QJsonObject uploadJsonObj = uploadJsonDoc.object();
                qDebug() << "Thread" << QThread::currentThreadId() << ": Upload JSON:" << uploadJsonObj;
                scanData.rawVtResponse = QString::fromUtf8(uploadResponseData); // Обновляем на ответ от загрузки

                int uploadResponseCode = uploadJsonObj.value("response_code").toInt(-1);
                if (uploadResponseCode == 1) { // Файл успешно поставлен в очередь
                    scanData.scanId = uploadJsonObj.value("scan_id").toString();
                    // Теперь нужно периодически запрашивать отчет
                    scanData.status = "В очереди VT (ожидание отчета)";
                    emit scanResultReady(scanData, row); // Обновим статус в таблице

                    // Цикл опроса отчета (с задержками)
                    int retries = 0;
                    const int maxRetries = 12;
                    bool reportReceived = false;
                    while(retries < maxRetries && !reportReceived) {
                        QThread::sleep(15);
                        retries++;
                        qDebug() << "Thread" << QThread::currentThreadId() << ": Polling for report, attempt" << retries;

                        QUrlQuery pollQuery;
                        pollQuery.addQueryItem("apikey", m_apiKey);
                        pollQuery.addQueryItem("resource", fileHash);
                        QNetworkRequest pollReportRequest(QUrl("https://www.virustotal.com/vtapi/v2/file/report?" + pollQuery.toString(QUrl::FullyEncoded)));
                        pollReportRequest.setRawHeader("Accept", "application/json");

                        QNetworkReply *pollReply = localNam.get(pollReportRequest);
                        connect(pollReply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
                        loop.exec();

                        if (pollReply->error() == QNetworkReply::NoError) {
                            QByteArray pollResponseData = pollReply->readAll();
                            QJsonDocument pollJsonDoc = QJsonDocument::fromJson(pollResponseData);
                            QJsonObject pollJsonObj = pollJsonDoc.object();
                            scanData.rawVtResponse = QString::fromUtf8(pollResponseData); // Обновляем на последний ответ

                            if (pollJsonObj.value("response_code").toInt(-1) == 1) {
                                scanData.scanTime = pollJsonObj.value("scan_date").toString();
                                int positives = pollJsonObj.value("positives").toInt(0);
                                int total = pollJsonObj.value("total").toInt(0);
                                scanData.vtResult = QString("%1/%2").arg(positives).arg(total);
                                scanData.status = "Завершено (Загружен)";
                                reportReceived = true;

                                // todo через главный поток
                                QSqlQuery dbQuery(m_db);
                                dbQuery.prepare("REPLACE INTO scan_results (hash_md5, file_name, file_size, scan_time, vt_result, raw_vt_response) "
                                                "VALUES (:hash, :name, :size, :time, :result, :raw)");
                                dbQuery.bindValue(":hash", scanData.hashMD5);
                                dbQuery.bindValue(":name", scanData.fileName);
                                dbQuery.bindValue(":size", scanData.fileSize);
                                dbQuery.bindValue(":time", scanData.scanTime);
                                dbQuery.bindValue(":result", scanData.vtResult);
                                dbQuery.bindValue(":raw", scanData.rawVtResponse);
                                if (!dbQuery.exec()) {
                                    qWarning() << "Thread" << QThread::currentThreadId() << "DB Error on replace (polled report):" << dbQuery.lastError().text();
                                }
                            } else if (pollJsonObj.value("response_code").toInt(-1) == 0) {
                                // Отчет еще не готов, продолжаем опрос
                                scanData.status = QString("В очереди VT (попытка %1/%2)").arg(retries).arg(maxRetries);
                                emit scanResultReady(scanData, row); // Промежуточное обновление статуса
                            } else {
                                // Ошибка при получении отчета после загрузки
                                scanData.status = "Ошибка VT: " + pollJsonObj.value("verbose_msg").toString();
                                reportReceived = true; // Прекращаем опрос
                            }
                        } else {
                            scanData.status = "Сетевая ошибка при опросе: " + pollReply->errorString();
                            reportReceived = true; // Прекращаем опрос
                        }
                        pollReply->deleteLater();
                    } // end while polling

                    if (!reportReceived) {
                        scanData.status = "Таймаут ожидания отчета VT";
                    }
                } else { // Ошибка при загрузке файла
                    scanData.status = "Ошибка загрузки: " + uploadJsonObj.value("verbose_msg").toString();
                }
            } else { // Сетевая ошибка при загрузке
                scanData.status = "Сетевая ошибка (загрузка): " + uploadReply->errorString();
            }
            uploadReply->deleteLater();

        } else if (responseCode == -2) { // Ресурс находится в очереди на анализ
            scanData.status = "В очереди VT (ожидание)";
            scanData.vtResult = "Pending...";
        }
        else {
            scanData.status = "Ошибка VT: " + jsonObj.value("verbose_msg").toString();
            scanData.vtResult = "Error";
        }
    } else {
        scanData.status = "Сетевая ошибка (отчет): " + reportReply->errorString();
        scanData.vtResult = "N/A";
        qWarning() << "Thread" << QThread::currentThreadId() << "Network error on report request:" << reportReply->errorString();
    }

    reportReply->deleteLater();
    emit scanResultReady(scanData, row); // отправляем финальный результат/статус
    qDebug() << "Thread" << QThread::currentThreadId() << ": Scan task finished for hash" << fileHash;
}


// Слот для обновления GUI
void MainWindow::updateTableWithScanResult(const ScanResult& result, int row) {
    if (row < 0 || row >= m_model->rowCount()) {
        // пробуем найти по хэшу, если row некорректен
        row = findRowByHash(result.hashMD5);
        if (row < 0) {
            qWarning() << "Не удалось найти строку для обновления результата хэша:" << result.hashMD5;
            return;
        }
    }

    m_model->item(row, COL_NAME)->setText(result.fileName); // На случай если имя файла уточнилось
    m_model->item(row, COL_SIZE)->setText(QString::number(result.fileSize) + " B");
    m_model->item(row, COL_HASH)->setText(result.hashMD5);
    m_model->item(row, COL_SCAN_TIME)->setText(result.scanTime);
    m_model->item(row, COL_VT_RESULT)->setText(result.vtResult);
    m_model->item(row, COL_STATUS)->setText(result.status);

    // Обновляем данные в UserRole
    QStandardItem *nameItem = m_model->item(row, COL_NAME);
    QVariantMap itemData = nameItem->data(Qt::UserRole).toMap();
    itemData["status"] = result.status;
    itemData["needsScan"] = result.needsScan; // обновится, если скан завершен
    itemData["rawVtResponse"] = result.rawVtResponse; // сохрянаем полный ответ
    nameItem->setData(itemData, Qt::UserRole);

    statusBar()->showMessage(QString("Результат для %1 (%2): %3").arg(result.fileName, result.hashMD5, result.status), 5000);
}
