#include "change_debug.h"
#include "ui_change_debug.h"

Change_debug::Change_debug(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Change_debug)
{
    ui->setupUi(this);

    QProcess* m_proces_bash = new QProcess;
    m_proces_bash->setProcessEnvironment(QProcessEnvironment::systemEnvironment());


    m_proces_bash->start("./cmdtool debug show\n");

    if (m_proces_bash->waitForStarted() && m_proces_bash->waitForFinished()){
        QByteArray output = m_proces_bash->readAllStandardOutput();
        QString outputString(output);
        ui -> current_debug_level -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> current_debug_level -> setText("Fail to connect.");
    }

}

Change_debug::~Change_debug()
{
    delete ui;
}

void Change_debug::on_commit_button_clicked()
{

    /* get the text in the lineedit */
    QString level = ui -> input -> text();

    QProcess* process = new QProcess;
    process->setProcessEnvironment(QProcessEnvironment::systemEnvironment());

    QString command = "./cmdtool debug set " + level;
    process->start(command);

    if (process->waitForStarted() && process->waitForFinished()){
        QString outputString = "The new debug level is " + level;
//        QByteArray output = process->readAllStandardOutput();
//        QString outputString(output);
        ui -> new_debug_level -> setText(outputString);
    }
    else
    {
        // 处理启动失败或执行超时的情况
        ui -> new_debug_level -> setText("Fail to connect.");
    }

}
