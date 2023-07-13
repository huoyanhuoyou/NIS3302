#ifndef MODIFY_RULE_H
#define MODIFY_RULE_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class Modify_rule;
}

class Modify_rule : public QWidget
{
    Q_OBJECT

public:
    explicit Modify_rule(QWidget *parent = nullptr);
    ~Modify_rule();

private slots:
    void on_commit_button_clicked();

private:
    Ui::Modify_rule *ui;
};

#endif // MODIFY_RULE_H
