cmake_policy(SET CMP0091 NEW)
cmake_minimum_required(VERSION 3.15)
project(mini_detour)

if(APPLE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

set(CMAKE_C_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)
set(CMAKE_CXX_STANDARD_LIBRARIES "" CACHE STRING "" FORCE)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MINIDETOUR_DYNAMIC_RUNTIME "Link against dynamic runtime (Windows)" ON)
option(MINIDETOUR_BUILD_TESTS "Build tests" OFF)

set(MINIDETOUR_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/include/mini_detour/mini_detour.h
)

set(CAPSTONE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/cs.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCInst.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCInstrDesc.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCRegisterInfo.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/SStream.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/utils.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMDisassembler.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMInstPrinter.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMMapping.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMModule.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64BaseInfo.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64Disassembler.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64InstPrinter.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64Mapping.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64Module.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86Disassembler.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86DisassemblerDecoder.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86IntelInstPrinter.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86Mapping.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86Module.c
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86ATTInstPrinter.c
)

set(CAPSTONE_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/arm64.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/arm.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/capstone.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/evm.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/mips.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/ppc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/x86.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/sparc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/systemz.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/xcore.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/m68k.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/tms320c64x.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/m680x.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/mos65xx.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include/capstone/platform.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/cs_priv.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/LEB128.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MathExtras.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCDisassembler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCFixedLenDisassembler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCInst.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCInstrDesc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/MCRegisterInfo.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/SStream.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/utils.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMAddressingModes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMBaseInfo.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMDisassembler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMGenAsmWriter.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMGenDisassemblerTables.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMGenInstrInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMGenRegisterInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMGenSubtargetInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMInstPrinter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/ARM/ARMMapping.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64AddressingModes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64BaseInfo.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64Disassembler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64GenAsmWriter.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64GenDisassemblerTables.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64GenInstrInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64GenRegisterInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64GenSubtargetInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64InstPrinter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/AArch64/AArch64Mapping.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86BaseInfo.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86Disassembler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86DisassemblerDecoder.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86DisassemblerDecoderCommon.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenAsmWriter.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenAsmWriter1.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenAsmWriter1_reduce.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenAsmWriter_reduce.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenDisassemblerTables.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenDisassemblerTables_reduce.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenInstrInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenInstrInfo_reduce.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86GenRegisterInfo.inc
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86InstPrinter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/arch/X86/X86Mapping.h
)

add_library(
  mini_detour
  src/mini_detour.cpp
  src/mini_detour_arm.h
  src/mini_detour_arm64.h
  src/mini_detour_x86.h
  src/mini_detour_x64.h
  src/mini_detour_linux.h
  src/mini_detour_macos.h
  src/mini_detour_windows.h
  include/mini_detour/mini_detour.h
  
  ${CAPSTONE_HEADERS}
  ${CAPSTONE_SOURCES}
)

set_target_properties(mini_detour PROPERTIES
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<BOOL:${MINIDETOUR_DYNAMIC_RUNTIME}>:DLL>"
  POSITION_INDEPENDENT_CODE ON
  C_VISIBILITY_PRESET hidden
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
)

target_link_libraries(
  mini_detour
  PUBLIC
    
  $<$<BOOL:${WIN32}>:shell32>
  # For library UNIX loading
  $<$<NOT:$<BOOL:${WIN32}>>:dl>
)

target_compile_definitions(
  mini_detour
  PRIVATE
  -DCAPSTONE_USE_SYS_DYN_MEM
  -DCAPSTONE_HAS_X86
  -DCAPSTONE_HAS_ARM64
  -DCAPSTONE_HAS_ARM
)

target_compile_options(
  mini_detour
  PRIVATE
  $<$<BOOL:${MSVC}>:/MP>
)

target_include_directories(
  mini_detour
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include>
  $<INSTALL_INTERFACE:include>
)

if(APPLE)
  add_executable(
    macos_permission_fix
    tests/macos_permission_fix.cpp
  )

  set_target_properties(macos_permission_fix PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
endif()

if(MINIDETOUR_BUILD_TESTS)
  add_library(
    export_hook_test_library SHARED
    tests/dll_test.c
  )

  set_target_properties(export_hook_test_library PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<BOOL:${MINIDETOUR_DYNAMIC_RUNTIME}>:DLL>"
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    PREFIX ""
  )

  add_library(
    mini_detour_test
    src/mini_detour.cpp
    src/mini_detour_arm.h
    src/mini_detour_arm64.h
    src/mini_detour_x86.h
    src/mini_detour_x64.h
    src/mini_detour_linux.h
    src/mini_detour_macos.h
    src/mini_detour_windows.h
    include/mini_detour/mini_detour.h
    
    ${CAPSTONE_HEADERS}
    ${CAPSTONE_SOURCES}
  )
  
  set_target_properties(mini_detour_test PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<BOOL:${MINIDETOUR_DYNAMIC_RUNTIME}>:DLL>"
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    CXX_STANDARD 14
  )
  
  target_link_libraries(
    mini_detour_test
    PUBLIC
    
    $<$<BOOL:${WIN32}>:shell32>
    # For library UNIX loading
    $<$<NOT:$<BOOL:${WIN32}>>:dl>
  )
  
  target_compile_definitions(
    mini_detour_test
    PRIVATE
    -DCAPSTONE_USE_SYS_DYN_MEM
    -DCAPSTONE_HAS_X86
    -DCAPSTONE_HAS_ARM64
    -DCAPSTONE_HAS_ARM
    USE_SPDLOG
    $<$<BOOL:${WIN32}>:_SILENCE_ALL_MS_EXT_DEPRECATION_WARNINGS>
  )
  
  target_compile_options(
    mini_detour_test
    PRIVATE
    $<$<BOOL:${MSVC}>:/MP>
  )
  
  target_include_directories(
    mini_detour_test
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/deps/capstone/include>
    $<INSTALL_INTERFACE:include>
  )

  add_executable(
    tests
    tests/test.cpp
  )
  
  set_target_properties(tests PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>$<$<BOOL:${MINIDETOUR_DYNAMIC_RUNTIME}>:DLL>"
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    CXX_STANDARD 14
  )

  target_link_libraries(
    tests
    PRIVATE
    mini_detour_test
    # For library UNIX loading
    $<$<NOT:$<BOOL:${WIN32}>>:dl>
  )

  target_include_directories(
    tests
    PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  )
  
  target_compile_definitions(
    tests
    PRIVATE
    $<$<BOOL:${WIN32}>:_SILENCE_ALL_MS_EXT_DEPRECATION_WARNINGS>
  )

endif()

add_library(Nemirtingas::MiniDetour ALIAS mini_detour)
set_target_properties(mini_detour PROPERTIES EXPORT_NAME MiniDetour)

##################
## Install rules
install(TARGETS mini_detour EXPORT MiniDetourTargets
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(FILES ${MINIDETOUR_HEADERS}
  DESTINATION include/mini_detour
)

# Export targets
install(
  EXPORT MiniDetourTargets
  FILE MiniDetourConfig.cmake
  NAMESPACE Nemirtingas::
  DESTINATION lib/cmake/MiniDetour
)
