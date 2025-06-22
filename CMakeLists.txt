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
add_subdirectory(third_party/googletest EXCLUDE_FROM_ALL)

# Test: IPv4 curl + pcap verify
add_test(NAME CurlIPv4Test
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verify_pcap.py curl -4 https://google.com
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Test: IPv6 curl + pcap verify
add_test(NAME CurlIPv6Test
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/verify_pcap.py curl -6 https://google.com
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Installation configuration
include(GNUInstallDirs)

# Install the shared library
install(TARGETS netspy
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install CLI frontend script
install(PROGRAMS netspy
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install helper scripts
install(FILES generate_bindings.py verify_pcap.py
    DESTINATION ${CMAKE_INSTALL_DATADIR}/netspy
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
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

# Install man page
install(FILES netspy.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)

# Build unit tests
if(BUILD_TESTING)
    add_executable(netspy_tests tests/regex_filter_test.cpp)
    target_include_directories(netspy_tests PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR} 
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(netspy_tests PRIVATE 
        gtest_main 
        dl 
        pcap 
        Threads::Threads
    )
    
    # Add test to CTest
    add_test(NAME NetSpyRegexFilterTest COMMAND netspy_tests)
endif()
