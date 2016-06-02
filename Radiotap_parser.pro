QT += core
QT -= gui

CONFIG += c++11

TARGET = Radiotap_parser
CONFIG += console
CONFIG -= app_bundle

LIBS += -lpcap

TEMPLATE = app

SOURCES += main.cpp
