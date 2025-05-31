cmake_minimum_required(VERSION 3.10) 
project(VirusTotalChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON) 

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt5 COMPONENTS Core Gui Widgets Network Sql REQUIRED)

add_executable(VirusTotalChecker
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    stylesheet.qss
    resources.qrc
)

target_link_libraries(VirusTotalChecker PRIVATE
    Qt5::Core
    Qt5::Gui
    Qt5::Widgets
    Qt5::Network
    Qt5::Sql
)