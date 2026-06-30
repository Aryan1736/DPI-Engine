cmake_minimum_required(VERSION 3.16)

project(DPIEngine)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(
    dpi_engine
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)