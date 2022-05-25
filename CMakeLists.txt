cmake_minimum_required(VERSION 3.17)
project(fusee_toy)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_PREFIX_PATH /usr/include)
SET(CMAKE_CXX_FLAGS_DEBUG "-g")

add_executable(fusee_toy main.cpp PayloadConstructor.cpp PayloadConstructor.h UsbCommsLinux.cpp UsbCommsLinux.h UsbComms.cpp UsbComms.h)

target_include_directories(fusee_toy PUBLIC usb-1.0)
target_link_libraries(fusee_toy usb-1.0)