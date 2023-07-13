#ifndef VIEW_DEBUG_H
#define VIEW_DEBUG_H

#include <QWidget>
#include "Head.h"

namespace Ui {
class View_debug;
}

class View_debug : public QWidget
{
    Q_OBJECT

public:
    explicit View_debug(QWidget *parent = nullptr);
    ~View_debug();

private:
    Ui::View_debug *ui;
};

#endif // VIEW_DEBUG_H
