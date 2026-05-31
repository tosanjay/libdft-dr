# libdft-dr -- DynamoRIO-native dynamic taint analysis library.
#
# Build:
#   cd libdft-dr
#   cmake -B build -DDynamoRIO_DIR=$DR_ROOT/cmake
#   cmake --build build -j
# where DR_ROOT=/path/to/dynamorio-11.3.0  (DR 11.3 is the supported baseline;
# DR 10.x worked through M5 but SIGFPEs on glibc 2.39 / Ubuntu 24.04).
#
# Layout (M3.2):
#   src/, include/libdft_dr/   -- the library + public headers
#   clients/<name>/            -- one DR client per reference pattern
#                                 (each loads as `drrun -c <name>.so -- app`)
#
# v0.1 ships libdft-dr as a STATIC archive that each client links into its
# own .so; this avoids the DR private-loader's shared-dependency handling
# during initial bringup. The Q-API.5 SHARED packaging plan is revisited in
# M5 (public docs / packaging).
cmake_minimum_required(VERSION 3.10)
project(libdft_dr C CXX)

if (NOT DEFINED DynamoRIO_DIR AND DEFINED ENV{DR_ROOT})
    set(DynamoRIO_DIR "$ENV{DR_ROOT}/cmake" CACHE PATH "DynamoRIO cmake dir")
endif ()

find_package(DynamoRIO REQUIRED)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO not found. Pass -DDynamoRIO_DIR=$DR_ROOT/cmake")
endif ()

# C++17: EWAHBoolArray's heavy template tags miscompile against this
# libstdc++ under -std=gnu++14.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# libdft-dr (STATIC) -- internals + libdft_dr::* public-API wrappers
# ---------------------------------------------------------------------------
add_library(libdft-dr STATIC
    # public-API wrappers
    src/api_lifecycle.cpp
    src/api_tag.cpp
    src/api_sources.cpp
    src/api_sinks.cpp
    # internals (top-level files; src/ migration is a v0.2 cosmetic)
    libdft_api_dr.cpp
    syscall_desc_dr.cpp
    tagmap.cpp
    osutils_dr.cpp
    mnt_consumer_dr.cpp
    sdft_summaries_dr.cpp
    sdft_hook_dr.cpp
    libdft_core_dr.cpp)
target_include_directories(libdft-dr
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/EWAHBoolArray)
# Pick up DR include paths + extension headers. configure_DynamoRIO_client on
# a STATIC target sets only the include/compile flags we need (no link side).
configure_DynamoRIO_client(libdft-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(libdft-dr ${ext})
endforeach ()
# Position-independent so the final client .so can link us in.
set_target_properties(libdft-dr PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Reference clients (each its own subdir)
# ---------------------------------------------------------------------------
add_subdirectory(clients/vuzzer_cmp_sink)
add_subdirectory(clients/file_introspect)
add_subdirectory(clients/egress_sanitizer)
add_subdirectory(clients/synthetic_unit)

# ---------------------------------------------------------------------------
# Legacy single-shot tool (tools/libdft-dta-dr.cpp).
# Kept building for parity A/B during M3.2 step 3; will be deleted once the
# vuzzer_cmp_sink client passes the parity gate.
# ---------------------------------------------------------------------------
add_library(libdft-dta-dr SHARED tools/libdft-dta-dr.cpp)
target_include_directories(libdft-dta-dr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
configure_DynamoRIO_client(libdft-dta-dr)
target_link_libraries(libdft-dta-dr libdft-dr)
foreach (ext drmgr drreg drx drwrap drsyms drutil)
    use_DynamoRIO_extension(libdft-dta-dr ${ext})
endforeach ()
set_target_properties(libdft-dta-dr PROPERTIES OUTPUT_NAME "libdft-dta-dr" PREFIX "")
