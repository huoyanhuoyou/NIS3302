QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    add_rule.cpp \
    block_rule.cpp \
    change_debug.cpp \
    delete_rule.cpp \
    display_log.cpp \
    icmp_help.cpp \
    main.cpp \
    modify_rule.cpp \
    view_debug.cpp \
    view_rule.cpp \
    widget.cpp

HEADERS += \
    Head.h \
    add_rule.h \
    block_rule.h \
    change_debug.h \
    delete_rule.h \
    display_log.h \
    icmp_help.h \
    modify_rule.h \
    view_debug.h \
    view_rule.h \
    widget.h

FORMS += \
    add_rule.ui \
    block_rule.ui \
    change_debug.ui \
    delete_rule.ui \
    display_log.ui \
    icmp_help.ui \
    modify_rule.ui \
    view_debug.ui \
    view_rule.ui \
    widget.ui

QMAKE_LFLAGS += -no-pie

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
