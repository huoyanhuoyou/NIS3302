#ifndef DISPLAY_LOG_H
#define DISPLAY_LOG_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class Display_log;
}

class Display_log : public QWidget
{
    Q_OBJECT

public:
    explicit Display_log(QWidget *parent = nullptr);
    ~Display_log();

private:
    Ui::Display_log *ui;
};

#endif // DISPLAY_LOG_H
