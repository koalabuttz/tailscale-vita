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
# BGFTP's gdc self carries a 4 MB memory budget in control-info-6
# (MEMSIZE 4096). A gdc runs foreground briefly so 0 also works, but we
# match BGFTP exactly to remove variables.
add_executable(spike_launcher src/launcher.c)
target_link_libraries(spike_launcher
  SceBgAppUtil_stub
  SceSysmodule_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  SceLibKernel_stub
  SceKernelThreadMgr_stub)
vita_create_self(eboot.bin spike_launcher UNSAFE MEMSIZE 4096)

# --- background service (eboot2.bin, gdd) ----------------------------
# THE FIX (2026-07-10): a background app is a "system mode app" and MUST
# declare a nonzero memory budget in the SELF's control-info-6, or the
# shell has no partition to spawn it into and StartBgApp fails with
# "could not find application". vita-make-fself:
#   -m  (MEMSIZE 16384)  memory budget in KB  -> ctrl-info-6 word3
#   -at (ATTRIBUTE 3)    attribute word       -> ctrl-info-6 word1
# These are exactly BGFTP's gdd values (16384 KB = 16 MB budget for its
# 14 MB heap; attribute 3). The installer copies both into app.db
# (#3705752058=16384, #3931254609=3); our old build left them 0.
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
vita_create_self(eboot2.bin spike_bgapp UNSAFE MEMSIZE 16384 ATTRIBUTE 3)
