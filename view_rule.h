#ifndef VIEW_RULE_H
#define VIEW_RULE_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class View_rule;
}

class View_rule : public QWidget
{
    Q_OBJECT

public:
    explicit View_rule(QWidget *parent = nullptr);

    ~View_rule();

private slots:


private:
    Ui::View_rule *ui;
};

#endif // VIEW_RULE_H
