#ifndef CHANGE_DEBUG_H
#define CHANGE_DEBUG_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class Change_debug;
}

class Change_debug : public QWidget
{
    Q_OBJECT

public:
    explicit Change_debug(QWidget *parent = nullptr);
    ~Change_debug();

private slots:
    void on_commit_button_clicked();

private:
    Ui::Change_debug *ui;
};

#endif // CHANGE_DEBUG_H
