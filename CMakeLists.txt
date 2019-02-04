set(ENV{ZEPHYR_BASE} "/absolute/path/to/zephyr")
set(ENV{GCCARMEMB_TOOLCHAIN_PATH} "/usr/")
set(ENV{ZEPHYR_TOOLCHAIN_VARIANT} "gccarmemb")
set(BOARD "96b_nitrogen")

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

FILE(GLOB app_sources src/*.c src/**/*.c)
target_sources(app PRIVATE ${app_sources})
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/subsys/net/ip)
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/ext/lib/encoding/tinycbor/src)
