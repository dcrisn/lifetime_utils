cmake_minimum_required(VERSION 3.25)

PROJECT(
    "lifetime-utils"
    VERSION 0.0.1
    DESCRIPTION "C++ header-only library for safe handling of object lifetimes"
    LANGUAGES C CXX
    )

# Generate compile-commands.json required for clangd language server.
SET(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_options(
    -Wall
    -Wextra
    -Wuninitialized
    -Wshadow
    -Wpedantic
    -Wnull-dereference
    -fwrapv
    -fstack-protector-all
    -fstrict-aliasing
    -Wstrict-aliasing
    -fdiagnostics-color=always
    -Wno-format-truncation
    -Wold-style-cast
    )

add_definitions(
    -D_POSIX_C_SOURCE=200809L
    # add functions from endian.h. Note the header and function names are
    # slightly different on the BSDs */
    -D_DEFAULT_SOURCE  # Linux, GNU libc (but probably musl etc)
    )

if (DEBUG)
    message("This is a *DEBUG* build")
    add_compile_options(-ggdb3)
    add_definitions(-DDEBUG_BUILD)
else()
    message("This is a *PRODUCTION* build")
    add_compile_options(-O3)
    add_compile_options(-Werror)
    #add_definitions(-DNDEBUG)  # strip out asserts
endif()

# set language standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

# throw an error if standard not implemented instead of trying to compile
# with older standard.
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# actually stick to c11/c++11 proper: don't use gnu11 -- i.e. do not use
# compiler-specific extensions
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

# make Makefiles spit out verbose output by default
set(CMAKE_VERBOSE_MAKEFILE ON)

SET(PUBLIC_HEADERS ${PROJECT_SOURCE_DIR}/include)

add_library(lifetime_utils INTERFACE
)

add_library(tarp::lifetime_utils ALIAS lifetime_utils)

target_include_directories(lifetime_utils INTERFACE
    $<INSTALL_INTERFACE:include>
)

install(FILES
    ${PUBLIC_HEADERS}/tarp/lifetime_utils.hpp
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tarp/
	)

# Where to put the cmake files that can be used by other cmake projects;
# NOTE: CMAKE_INSTALL_LIBDIR is from the GNUInstallDirs import.
SET(CMAKE_INSTALLATION_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/tarp/)

SET(version_config_file ${PROJECT_BINARY_DIR}/tarp_lifetime_utils-config-version.cmake)
SET(project_config_file ${PROJECT_BINARY_DIR}/tarp_lifetime_utils-config.cmake)

SET(CMAKE_EXPORT_FILE "tarp_lifetime_utils-targets")

INSTALL(TARGETS lifetime_utils
    EXPORT ${CMAKE_EXPORT_FILE}
    LIBRARY DESTINATION lib/
    ARCHIVE DESTINATION lib/
    RUNTIME DESTINATION bin/
)

# Some standard paths according to gnu guidelines
include(GNUInstallDirs)

# CMake helpers for generating a package config file (used below).
include(CMakePackageConfigHelpers)

SET(LIFETIME_UTILS_VERSION_STRING "0.0.1")

# Generate the package-version cmake config file into the build directory
write_basic_package_version_file(
    ${version_config_file}
    VERSION ${LIFETIME_UTILS_VERSION_STRING}
    COMPATIBILITY SameMajorVersion)

# generate the config.cmake file into the build directory.
# this file is used by cmake's find_package.
# Allow other projects to do: find_package(tarp_lifetime_utils).
configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/tarp_lifetime_utils-config.cmake.in
    ${project_config_file}
    INSTALL_DESTINATION ${CMAKE_INSTALLATION_DIR})

# Install the actual cmake exports file that previous commands
# have gradually populated.
INSTALL(
    EXPORT ${CMAKE_EXPORT_FILE}
    DESTINATION ${CMAKE_INSTALLATION_DIR}
    NAMESPACE tarp::
)

# Install config.cmake and config-version.cmake files.
install(
    FILES
       ${project_config_file}
       ${version_config_file}
    DESTINATION
       ${CMAKE_INSTALLATION_DIR}
)

