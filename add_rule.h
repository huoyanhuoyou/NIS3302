#ifndef ADD_RULE_H
#define ADD_RULE_H

#include <QWidget>
#include "Head.h"
#include "icmp_help.h"

namespace Ui {
class Add_rule;
}

class Add_rule : public QWidget
{
    Q_OBJECT

public:
    explicit Add_rule(QWidget *parent = nullptr);
    ~Add_rule();

private slots:
    void on_commit_button_clicked();

    void on_icmp_help_clicked();

private:
    Ui::Add_rule *ui;
};

#endif // ADD_RULE_H
