#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}


void Widget::on_add_rule_button_clicked()
{
    Add_rule *add_rule = new Add_rule;
    add_rule -> show();
}

void Widget::on_view_rule_button_clicked()
{
    View_rule *view_rule = new View_rule;
    view_rule -> show();
}

void Widget::on_delete_rule_button_clicked()
{
    Delete_rule *delete_rule = new Delete_rule;
    delete_rule -> show();
}

void Widget::on_view_debug_level_clicked()
{
    View_debug *view_debug = new View_debug;
    view_debug -> show();
}

void Widget::on_change_rule_button_clicked()
{
    Change_debug *change_debug = new Change_debug;
    change_debug -> show();
}

void Widget::on_block_rule_button_clicked()
{
    Block_rule *block_rule = new Block_rule;
    block_rule -> show();
}

void Widget::on_modify_rule_button_clicked()
{
    Modify_rule *modify_rule = new Modify_rule;
    modify_rule -> show();
}

void Widget::on_display_log_button_clicked()
{
    Display_log *display = new Display_log;
    display -> show();
}
