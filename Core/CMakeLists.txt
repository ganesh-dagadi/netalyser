cmake_minimum_required(VERSION 3.0)
project(netalyse)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the executable target
add_executable(netalyser netalyser.cpp)

# Define the library target
add_library(packetSniffer lib/packetSniffer.cpp)

# Link the library target against libpcap
target_link_libraries(packetSniffer PUBLIC pcap)

# Link the executable target against the library target
target_link_libraries(netalyser PRIVATE packetSniffer)
