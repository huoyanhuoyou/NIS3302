#include "delete_rule.h"
#include "ui_delete_rule.h"

Delete_rule::Delete_rule(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Delete_rule)
{
    ui->setupUi(this);

    /* create a new process */
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

Delete_rule::~Delete_rule()
{
    delete ui;
}

void Delete_rule::on_commit_button_clicked()
{

    /* get the text in the lineedit */
    QString number = ui -> input_line -> text();

    QProcess* process = new QProcess;
    process->setProcessEnvironment(QProcessEnvironment::systemEnvironment());

    QString command = "./cmdtool rule del " + number;

    process->start(command);

    if (process->waitForStarted() && process->waitForFinished()){

        QByteArray output = process->readAllStandardOutput();
        QString outputString(output);
        ui -> new_rule_list -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> new_rule_list -> setText("Fail to connect.");
    }



}
