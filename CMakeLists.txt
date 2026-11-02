# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

# Skip checking/cloning unused submodules automatically in CMake
set(ENV{IDF_SKIP_CHECK_SUBMODULES} "1")

add_compile_options(-w) # Turn off warnings until esp_tinyusb is updated IEC-86

# Support building for ESP32-P4 Rev < 3.0 (v1.x sample) by setting ESP32P4_REV1=1
if((DEFINED ENV{ESP32P4_REV1} AND "$ENV{ESP32P4_REV1}" STREQUAL "1") OR (DEFINED ESP32P4_REV1 AND ESP32P4_REV1))
    set(SDKCONFIG_DEFAULTS "sdkconfig.defaults;sdkconfig.defaults.esp32p4;sdkconfig.defaults.esp32p4_rev1")
endif()

# "Trim" the build. Include the minimal set of components, main, and anything it depends on.
set(COMPONENTS main)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(nesigner)
