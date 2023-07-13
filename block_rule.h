#ifndef BLOCK_RULE_H
#define BLOCK_RULE_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class Block_rule;
}

class Block_rule : public QWidget
{
    Q_OBJECT

public:
    explicit Block_rule(QWidget *parent = nullptr);
    ~Block_rule();

private slots:
    void on_commit_button_clicked();

private:
    Ui::Block_rule *ui;
};

#endif // BLOCK_RULE_H
