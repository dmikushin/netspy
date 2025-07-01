cmake_minimum_required(VERSION 3.10)
project(netspy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)

# Generate bindings header
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_bindings_header.hpp
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/generate_bindings.py ${CMAKE_CURRENT_SOURCE_DIR}/network_functions.json header > generated_bindings_header.hpp
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/generate_bindings.py network_functions.json
    COMMENT "Generating C++ bindings header from JSON"
)

# Generate bindings implementation
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_bindings_impl.hpp
    COMMAND Python3::Interpreter ${CMAKE_CURRENT_SOURCE_DIR}/generate_bindings.py ${CMAKE_CURRENT_SOURCE_DIR}/network_functions.json implementation > generated_bindings_impl.hpp
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/generate_bindings.py network_functions.json
    COMMENT "Generating C++ bindings implementation from JSON"
)

add_library(netspy SHARED netspy.cpp network_interceptor.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/generated_bindings_header.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/generated_bindings_impl.hpp)
target_include_directories(netspy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(netspy PRIVATE dl pcap Threads::Threads)

# Enable testing
include(CTest)
enable_testing()

# Add Google Test
add_subdirectory(ThirdParty/googletest EXCLUDE_FROM_ALL)

# Create test executable
add_executable(netspy_tests
    tests/pcap_over_ip_test.cpp
)

target_link_libraries(netspy_tests
    gtest
    gtest_main
    dl
    pthread
    pcap
)

target_include_directories(netspy_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ThirdParty/googletest/googletest/include
)

# Add Google Test cases
add_test(NAME PcapOverIPTests COMMAND netspy_tests)

# Test: IPv4 curl + pcap verify
add_test(NAME CurlIPv4Test
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_pcap.py curl -4 https://google.com
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test: IPv6 curl + pcap verify
add_test(NAME CurlIPv6Test
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/verify_pcap.py curl -6 https://google.com
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Installation configuration
include(GNUInstallDirs)

# Install the shared library
install(TARGETS netspy
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install configuration file
install(FILES network_functions.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netspy
)

# Install header files for development
install(FILES network_interceptor.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/netspy
)

# Install documentation
install(FILES README.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)
