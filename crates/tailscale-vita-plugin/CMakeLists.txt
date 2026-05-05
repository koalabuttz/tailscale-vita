cmake_minimum_required(VERSION 3.0)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK env var to point to your SDK path.")
  endif()
endif()

project(tailscale_vita_plugin C)
include("${VITASDK}/share/vita.cmake" REQUIRED)

# Linker/codegen flags lifted from vitacompanion + ftpeverywhere — the
# canonical *main SUPRX pattern. -fno-pic + -nostdlib are required.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O3 -fno-pic -fno-PIC -std=gnu99")

# Phase 1B: link the Rust staticlib produced by
#   cargo build --profile staticlib --target armv7-sony-vita-newlibeabihf
# (see build.sh). This shim exposes one symbol — `ts_vita_rt_hello` —
# which main.c calls from `module_start` after the C-side hello.
set(RUST_STATICLIB
  "${CMAKE_SOURCE_DIR}/../../target/armv7-sony-vita-newlibeabihf/staticlib/libtailscale_vita_rt.a"
  CACHE FILEPATH "tailscale-vita-rt staticlib")

if(NOT EXISTS "${RUST_STATICLIB}")
  message(FATAL_ERROR
    "Rust staticlib not found at ${RUST_STATICLIB}. "
    "Run build.sh (or cargo build --profile staticlib --target armv7-sony-vita-newlibeabihf -p tailscale-vita-rt) first.")
endif()

add_executable(${PROJECT_NAME}
  src/main.c)

target_link_libraries(${PROJECT_NAME}
  ${RUST_STATICLIB}
  taihen_stub
  SceIofilemgr_stub_weak
  # taipool needs sceKernelWaitSema (in SceLibKernel_stub_weak) and
  # sceKernelSignalSema (in SceKernelThreadMgr_stub_weak — split
  # across two libs because vitasdk's stubs mirror the Vita kernel's
  # mixed-NID ownership of the sema API). Wrap in --start-group so
  # ld rescans for cross-archive references rather than relying on
  # link order.
  -Wl,--start-group
  taipool
  SceLibKernel_stub_weak
  SceKernelThreadMgr_stub_weak
  k
  -Wl,--end-group
  # libgcc supplies __aeabi_* helpers (memcpy/memset/division) that the
  # Rust staticlib references via compiler-builtins.
  gcc)

set_target_properties(${PROJECT_NAME}
  PROPERTIES LINK_FLAGS "-nostdlib")

vita_create_self(${PROJECT_NAME}.suprx ${PROJECT_NAME}
  CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/tailscale_vita_plugin.yml
  UNSAFE)
