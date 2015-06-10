TEMPLATE = lib
CONFIG -= console
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += staticlib

QMAKE_CFLAGS += -std=gnu99

#DEFINES += GNU_SOURCE

SOURCES += \
    fins.c

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    fins.h
