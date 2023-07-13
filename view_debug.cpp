#include "view_debug.h"
#include "ui_view_debug.h"

View_debug::View_debug(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::View_debug)
{
    ui->setupUi(this);

    QProcess* m_proces_bash = new QProcess;
    m_proces_bash->setProcessEnvironment(QProcessEnvironment::systemEnvironment());


    m_proces_bash->start("./cmdtool debug show\n");

    if (m_proces_bash->waitForStarted() && m_proces_bash->waitForFinished()){
        QByteArray output = m_proces_bash->readAllStandardOutput();
        QString outputString(output);
        ui -> view_debug -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> view_debug -> setText("Fail to connect.");
    }
}

View_debug::~View_debug()
{
    delete ui;
}
