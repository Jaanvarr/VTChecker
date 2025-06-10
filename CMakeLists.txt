cmake_minimum_required(VERSION 3.10) 

project(VirusTotalChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON) 

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 COMPONENTS Core Gui Widgets Network Sql REQUIRED)

add_executable(VirusTotalChecker
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    stylesheet.qss
    resources.qrc
)

target_link_libraries(VirusTotalChecker PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    Qt6::Sql
)

