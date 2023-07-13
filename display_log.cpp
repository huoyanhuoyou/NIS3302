#include "display_log.h"
#include "ui_display_log.h"

Display_log::Display_log(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Display_log)
{
    ui->setupUi(this);

    /* create a new process */
    QProcess* m_proces_bash = new QProcess;
    m_proces_bash->setProcessEnvironment(QProcessEnvironment::systemEnvironment());

    m_proces_bash->start("dmesg\n");

    if (m_proces_bash->waitForStarted() && m_proces_bash->waitForFinished()){
        QByteArray output = m_proces_bash->readAllStandardOutput();
        QString outputString(output);
        ui -> result -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> result -> setText("Fail to connect.");
    }
}

Display_log::~Display_log()
{
    delete ui;
}
