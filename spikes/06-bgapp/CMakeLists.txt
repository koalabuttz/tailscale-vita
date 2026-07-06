cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK env var to point to your SDK path.")
  endif()
endif()

project(bgapp_spike C)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -std=gnu99")

# --- launcher (eboot.bin, gdc) ---------------------------------------
add_executable(spike_launcher src/launcher.c)
target_link_libraries(spike_launcher
  SceBgAppUtil_stub
  SceSysmodule_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  SceLibKernel_stub
  SceKernelThreadMgr_stub)
vita_create_self(eboot.bin spike_launcher UNSAFE)

# --- background service (eboot2.bin, gdd) ----------------------------
add_executable(spike_bgapp src/bgapp.c)
target_link_libraries(spike_bgapp
  SceNotificationUtil_stub
  SceSysmodule_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  SceLibKernel_stub
  SceKernelThreadMgr_stub
  SceSysmem_stub
  SceNet_stub
  SceNetCtl_stub)
vita_create_self(eboot2.bin spike_bgapp UNSAFE)
