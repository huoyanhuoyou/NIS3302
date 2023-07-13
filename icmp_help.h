#ifndef ICMP_HELP_H
#define ICMP_HELP_H

#include <QWidget>

namespace Ui {
class ICMP_help;
}

class ICMP_help : public QWidget
{
    Q_OBJECT

public:
    explicit ICMP_help(QWidget *parent = nullptr);
    ~ICMP_help();

private:
    Ui::ICMP_help *ui;
};

#endif // ICMP_HELP_H
