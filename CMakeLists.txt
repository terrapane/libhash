cmake_minimum_required(VERSION 3.21)

# Define the Cryptographic Hash Library project
project(libhash
        VERSION 1.0.12.0
        DESCRIPTION "Cryptographic Hash Library"
        LANGUAGES CXX)

# Set options depending on whether this is a subproject
if(PROJECT_IS_TOP_LEVEL)
    # Option to control whether tests are built
    option(libhash_BUILD_TESTS "Build Tests for Hash Library" ON)
else()
    # Option to control whether tests are built
    option(libhash_BUILD_TESTS "Build Tests for Hash Library" OFF)
endif()

# Option to control ability to install the library
option(libhash_INSTALL "Install the Hash Library" ON)

# Determine whether clang-tidy will be performed
option(libhash_CLANG_TIDY "Use clang-tidy to perform linting during build" OFF)

# Ensure testing is enabled to surface tests in dependencies
include(CTest)

add_subdirectory(dependencies)
add_subdirectory(src)

if(BUILD_TESTING AND libhash_BUILD_TESTS)
    add_subdirectory(test)
endif()
