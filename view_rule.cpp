#include "view_rule.h"
#include "ui_view_rule.h"

View_rule::View_rule(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::View_rule)
{
    ui->setupUi(this);

    QProcess* m_proces_bash = new QProcess;
    m_proces_bash->setProcessEnvironment(QProcessEnvironment::systemEnvironment());


    m_proces_bash->start("./cmdtool rule show\n");

    if (m_proces_bash->waitForStarted() && m_proces_bash->waitForFinished()){

        QByteArray output = m_proces_bash->readAllStandardOutput();
        QString outputString(output);
        ui -> rule_list -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> rule_list -> setText("Fail to connect.");
    }


}

View_rule::~View_rule()
{
    delete ui;
}

