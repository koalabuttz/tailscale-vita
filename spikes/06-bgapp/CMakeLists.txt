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

# Bisect variants for the round-2 silent-death signature (no log line,
# no core dump): r3a tests the pre-main heap-grant theory (1 MB heap),
# r3b additionally tests SELF-authority rejection (SAFE self — the
# shell-initiated bgapp spawn may not be covered by henkaku's
# unsafe-homebrew patches). Pushed directly over eboot2.bin via FTP.
add_executable(spike_bgapp_small src/bgapp.c)
target_compile_definitions(spike_bgapp_small PRIVATE SPIKE_HEAP_MB=1)
target_link_libraries(spike_bgapp_small
  SceNotificationUtil_stub
  SceSysmodule_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  SceLibKernel_stub
  SceKernelThreadMgr_stub
  SceSysmem_stub
  SceNet_stub
  SceNetCtl_stub)
vita_create_self(eboot2_r3a.bin spike_bgapp_small UNSAFE)

# vita_create_self can't be called twice on one executable target
# (its -velf helper target collides), so the SAFE variant gets a
# duplicate executable.
add_executable(spike_bgapp_small_safe src/bgapp.c)
target_compile_definitions(spike_bgapp_small_safe PRIVATE SPIKE_HEAP_MB=1)
target_link_libraries(spike_bgapp_small_safe
  SceNotificationUtil_stub
  SceSysmodule_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  SceLibKernel_stub
  SceKernelThreadMgr_stub
  SceSysmem_stub
  SceNet_stub
  SceNetCtl_stub)
vita_create_self(eboot2_r3b.bin spike_bgapp_small_safe)
