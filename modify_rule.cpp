#include "modify_rule.h"
#include "ui_modify_rule.h"

Modify_rule::Modify_rule(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Modify_rule)
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

Modify_rule::~Modify_rule()
{
    delete ui;
}

void Modify_rule::on_commit_button_clicked()
{

    /* get the text in the lineedit */
    QString number = ui -> rule_number -> text();

    QString item;
    if ( ui->item_option->currentText() == "Source IP Address" )
    {
        item = "-x";
    }
    else if ( ui->item_option->currentText() == "Source Port" )
    {
        item = "-y";
    }
    else if ( ui->item_option->currentText() == "Destination IP Address" )
    {
        item = "-m";
    }
    else if ( ui->item_option->currentText() == "Destination Port" )
    {
        item = "-n";
    }
    else if ( ui->item_option->currentText() == "Protocol" )
    {
        item = "-p";
    }
    else if (ui->item_option->currentText() == "Date" )
    {
        item = "-d";
    }
    else if (ui->item_option->currentText() == "Week" )
    {
        item = "-w";
    }
    else if (ui->item_option->currentText() == "Start Time" )
    {
        item = "-s";
    }
    else if ( ui->item_option->currentText() == "End Time" )
    {
        item = "-e";
    }
    else if ( ui->item_option->currentText() == "INDev mac" )
    {
        item = "-i";
    }
    else if ( ui->item_option->currentText() == "OUTDev mac" )
    {
        item = "-o";
    }
    else
    {
        item = "-t";
    }



    QString content = ui -> item_content -> text();



    if( item == "-w" ){

        QString week = content;
        if( week == "Sunday" || week == "sunday" )
        {
            content = "0";
        }
        else if( week == "Monday" || week == "monday" )
        {
            content = "1";
        }
        else if( week == "Tuesday" || week == "tuesday" )
        {
            content = "2";
        }
        else if( week == "Wednesday" || week == "wednesday" )
        {
            content = "3";
        }
        else if( week == "Thursday" || week == "thursday" )
        {
            content = "4";
        }
        else if( week == "Friday" || week == "friday" )
        {
            content = "5";
        }
        else
        {
            content = "6";
        }

    }



    /* make command */
    QString command = "./cmdtool rule alt " + number + " " + item + " " + content ;

    QProcess* process = new QProcess;
    process->setProcessEnvironment(QProcessEnvironment::systemEnvironment());

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
