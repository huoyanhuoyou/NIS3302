#include "add_rule.h"
#include "ui_add_rule.h"

Add_rule::Add_rule(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Add_rule)
{
    ui->setupUi(this);
}

Add_rule::~Add_rule()
{
    delete ui;
}

void Add_rule::on_commit_button_clicked()
{

    /* get the text in the lineedit */
    QString source_ip = ui->sip_1->text();
    bool sourceip = false;
    source_ip += ".";
    source_ip += ui->sip_2->text();
    source_ip += ".";
    source_ip += ui->sip_3->text();
    source_ip += ".";
    source_ip += ui->sip_4->text();
    if( source_ip == "..." )
    {
        sourceip = false;
    }
    else
    {
        sourceip = true;
    }
    if( sourceip ){
        if( ui->sip_1->text() == "" || ui->sip_2->text() == "" || ui->sip_3->text() == "" || ui->sip_4->text() == ""  ) {
            ui -> result -> setText("Invalid Source IP Address input!");
            return;
        }
    }

    /* source port */
    QString source_port = ui->sport->text();
    bool sourceport = false;
    if( source_port == "" )
    {
        sourceport = false;
    }
    else
    {
        sourceport = true;
    }

    /* dst ip */
    QString dst_ip = ui->dstip_1->text();
    bool dstip = false;
    dst_ip += ".";
    dst_ip += ui->dstip_2->text();
    dst_ip += ".";
    dst_ip += ui->dstip_3->text();
    dst_ip += ".";
    dst_ip += ui->dstip_4->text();
    if( dst_ip == "..." )
    {
        dstip = false;
    }
    else
    {
        dstip = true;
    }
    if( dstip ){
        if( ui->dstip_1->text() == "" || ui->dstip_2->text() == "" || ui->sip_3->text() == "" || ui->sip_4->text() == ""  ) {
            ui -> result -> setText("Invalid Destination IP Address input!");
            return;
        }
    }

    /* dst port */
    QString dst_port = ui->dport->text();
    bool dstport = false;
    if( dst_port == "" )
    {
        dstport = false;
    }
    else
    {
        dstport = true;
    }

    /* protocol */
    QString ptcl = ui->protocol->text();
    bool ptcl_exist = false;
    if( ptcl == "" )
    {
        ptcl_exist = false;
    }
    else
    {
        ptcl_exist = true;
    }

    /* date */
    QString dat = ui->date->currentText();
    bool date_exist = false;
    if( dat == "" )
    {
        date_exist = false;
    }
    else {
        date_exist = true;
    }


    /* week */
    QString wek;
    bool week_exist = false;
    if(ui->week->currentText() == "" )
    {
        week_exist = false;
    }
    else if(ui->week->currentText() == "Sunday")
    {
        week_exist = true;
        wek = "0";
    }
    else if(ui->week->currentText() == "Monday")
    {
        week_exist = true;
        wek = "1";
    }
    else if(ui->week->currentText() == "Tuesday")
    {
        week_exist = true;
        wek = "2";
    }
    else if(ui->week->currentText() == "Wednesday")
    {
        week_exist = true;
        wek = "3";
    }
    else if(ui->week->currentText() == "Thursday")
    {
        week_exist = true;
        wek = "4";
    }
    else if(ui->week->currentText() == "Friday")
    {
        week_exist = true;
        wek = "5";
    }
    else
    {
        week_exist = true;
        wek = "6";
    }

    /* start time */
    QString stime = ui->start_time->text();
    bool stime_exist = false;
    if( stime == "" )
    {
        stime_exist = false;
    }
    else {
        stime_exist = true;
    }

    /* end time */
    QString etime = ui->end_time->text();
    bool etime_exist = false;
    if( etime == "" )
    {
        etime_exist = false;
    }
    else {
        etime_exist = true;
    }

    /* IN DEV MAC */
    QString idev = ui->indev_mac->text();
    bool idev_exist = false;
    if( idev == "" )
    {
        idev_exist = false;
    }
    else {
        idev_exist = true;
    }

    /* OUT DEV MAC */
    QString odev = ui->outdev_mac->text();
    bool outdev_exist = false;
    if( odev == "" )
    {
        outdev_exist = false;
    }
    else {
        outdev_exist = true;
    }


    /* ICMP */
    QString ICMP = ui -> ICMP_type -> text();
    bool ICMP_exist = false;
    if ( ICMP == "" ){
        ICMP_exist = false;
    }
    else {
        ICMP_exist = true;
    }



    /* make command string */
    QString command = "./cmdtool rule add ";
    if( sourceip ){
        command += "-x ";
        command += source_ip;
        command += " ";
    }
    if( sourceport ){
        command += "-y ";
        command += source_port;
        command += " ";
    }
    if( dstip ){
        command += "-m ";
        command += dst_ip;
        command += " ";
    }
    if( dstport ){
        command += "-n ";
        command += dst_port;
        command += " ";
    }
    if( ptcl_exist ){
        command += "-p ";
        command += ptcl;
        command += " ";
    }
    if( date_exist ){
        command += "-d ";
        command += dat;
        command += " ";
    }
    if( week_exist ){
        command += "-w ";
        command += wek;
        command += " ";
    }
    if( stime_exist ){
        command += "-s ";
        command += stime;
        command += " ";
    }
    if( etime_exist ){
        command += "-e ";
        command += etime;
        command += " ";
    }
    if( idev_exist ){
        command += "-i ";
        command += idev;
        command += " ";
    }
    if( outdev_exist ){
        command += "-o ";
        command += odev;
        command += " ";
    }
    if( ICMP_exist ){
        command += "-t ";
        command += ICMP;
        command += " ";
    }


    /* create a new process */
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
        ui -> result -> setText("Fail to add new rule.");
    }


}

void Add_rule::on_icmp_help_clicked()
{
    ICMP_help *icmphelp = new ICMP_help;
    icmphelp -> show();
}
