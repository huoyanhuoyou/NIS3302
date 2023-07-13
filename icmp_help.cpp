#include "icmp_help.h"
#include "ui_icmp_help.h"

ICMP_help::ICMP_help(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ICMP_help)
{
    ui->setupUi(this);
}

ICMP_help::~ICMP_help()
{
    delete ui;
}
