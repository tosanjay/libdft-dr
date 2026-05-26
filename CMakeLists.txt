# libdft-dr -- DynamoRIO port of libdft64 (C.4). DR clients build with CMake
# (DR is CMake-native), separate from the Pin tree's GNU make.
#
# Build:
#   cd libdft-dr
#   cmake -B build -DDynamoRIO_DIR=$DR_ROOT/cmake
#   cmake --build build -j
# where DR_ROOT=/home/sanjay/san-home/tools/dynamorio-10.0
#
# Phase 2: source-painting taint foundation -- tagmap (shadow memory), the
# syscall source hooks, and the per-thread context + drmgr/drreg lifecycle.
# Opcode propagation (libdft_core) lands in Phases 3-5 of c4_dr_port_plan.md.
cmake_minimum_required(VERSION 3.10)
project(libdft_dr C CXX)

if (NOT DEFINED DynamoRIO_DIR AND DEFINED ENV{DR_ROOT})
    set(DynamoRIO_DIR "$ENV{DR_ROOT}/cmake" CACHE PATH "DynamoRIO cmake dir")
endif ()

find_package(DynamoRIO REQUIRED)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO not found. Pass -DDynamoRIO_DIR=$DR_ROOT/cmake")
endif ()

# C++17 (matches the working bbcounts2-dr client's default; EWAHBoolArray's
# heavy template tags miscompile against this libstdc++ under -std=gnu++14).
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(libdft-dta-dr SHARED
    tools/libdft-dta-dr.cpp
    libdft_api_dr.cpp
    syscall_desc_dr.cpp
    tagmap.cpp
    osutils_dr.cpp)
target_include_directories(libdft-dta-dr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
configure_DynamoRIO_client(libdft-dta-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(libdft-dta-dr ${ext})
endforeach ()

# Drop the lib prefix oddities: DR clients are loaded by path, so a stable
# name keeps config.py simple.
set_target_properties(libdft-dta-dr PROPERTIES OUTPUT_NAME "libdft-dta-dr" PREFIX "")
