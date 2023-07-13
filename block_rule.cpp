#include "block_rule.h"
#include "ui_block_rule.h"

Block_rule::Block_rule(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Block_rule)
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

Block_rule::~Block_rule()
{
    delete ui;
}

void Block_rule::on_commit_button_clicked()
{

    /* get the text in the lineedit */
    QString number = ui -> rule_number -> text();

    /* create a new process */
    QProcess* process = new QProcess;
    process->setProcessEnvironment(QProcessEnvironment::systemEnvironment());

    QString act;
     if(ui->action->currentText() == "Block" )
     {
         act = "0";
     }
     else {
         act = "1";
     }

    QString command = "./cmdtool rule set " + number + " " + act;
    process->start(command);

    if (process->waitForStarted() && process->waitForFinished()){
        QByteArray output = process->readAllStandardOutput();
        QString outputString(output);
        ui -> result -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> result -> setText("Fail to connect.");
    }


}
