#!/bin/sh

# Need to use before "make deploy" if boost libs dont have the correct path ...

BOOST_VERSION=1.65.1
otool -L chips-qt  | grep boost

install_name_tool -change /usr/local/opt/boost/lib/libboost_system.dylib /usr/local/Cellar/boost/$BOOST_VERSION/lib/libboost_system-mt.dylib chips-qt
install_name_tool -change /usr/local/opt/boost/lib/libboost_filesystem.dylib /usr/local/Cellar/boost/$BOOST_VERSION/lib/libboost_filesystem-mt.dylib chips-qt
install_name_tool -change /usr/local/opt/boost/lib/libboost_program_options-mt.dylib /usr/local/Cellar/boost/$BOOST_VERSION/lib/libboost_program_options-mt.dylib chips-qt
install_name_tool -change /usr/local/opt/boost/lib/libboost_thread-mt.dylib /usr/local/Cellar/boost/$BOOST_VERSION/lib/libboost_thread-mt.dylib chips-qt
install_name_tool -change /usr/local/opt/boost/lib/libboost_chrono-mt.dylib /usr/local/Cellar/boost/$BOOST_VERSION/lib/libboost_chrono-mt.dylib chips-qt

otool -L chips-qt  | grep boost

