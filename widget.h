#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

#include "add_rule.h"
#include "view_rule.h"
#include "delete_rule.h"
#include "view_debug.h"
#include "change_debug.h"
#include "block_rule.h"
#include "modify_rule.h"
#include "display_log.h"



QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void on_add_rule_button_clicked();

    void on_view_rule_button_clicked();

    void on_delete_rule_button_clicked();

    void on_view_debug_level_clicked();

    void on_change_rule_button_clicked();

    void on_block_rule_button_clicked();

    void on_modify_rule_button_clicked();

    void on_display_log_button_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
