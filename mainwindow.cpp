#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    RawSocketService rawSocketService = RawSocketService();
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    std::string from = ui->sourceIp->toPlainText().toStdString();
    std::string to = ui->destinationIp->toPlainText().toStdString();
    std::wstring dataStr = ui->message->toPlainText().toStdWString();
    rawSocketService.sendTCPPacket(from, to, dataStr);
}
