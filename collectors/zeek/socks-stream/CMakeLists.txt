cmake_minimum_required(VERSION 3.15)
project(SentinelSOCKSStream)
list(APPEND CMAKE_MODULE_PATH "${ZEEK_CMAKE_DIR}")
include(ZeekPlugin)
zeek_plugin_begin(Sentinel SOCKSStream)
zeek_plugin_cc(src/Plugin.cc src/Stream.cc)
zeek_plugin_end()
# Zeek's generated archive otherwise only depends on the native library.
add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/Sentinel_SOCKSStream.tgz" APPEND
 DEPENDS scripts/__load__.zeek scripts/main.zeek scripts/dpd.sig)
