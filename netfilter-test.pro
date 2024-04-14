TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    netfilter-test.c

LIBS += -lnetfilter_queue
