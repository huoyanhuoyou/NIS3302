#ifndef DELETE_RULE_H
#define DELETE_RULE_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class Delete_rule;
}

class Delete_rule : public QWidget
{
    Q_OBJECT

public:
    explicit Delete_rule(QWidget *parent = nullptr);
    ~Delete_rule();

private slots:
    void on_commit_button_clicked();

private:
    Ui::Delete_rule *ui;
};

#endif // DELETE_RULE_H
