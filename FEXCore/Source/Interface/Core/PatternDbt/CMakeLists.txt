# PatternDbt CMakeLists.txt
cmake_minimum_required(VERSION 3.10)

# 设置库名
set(LIB_NAME PatternDbt)

# 设置源文件列表
set(SRCS
  ../../Config/Config.cpp
  ../ArchHelpers/Arm64Emitter.cpp
  arm-asm.cpp
  arm-instr.cpp
  HostParse.cpp
  parse.cpp
  RiscvInst.cpp
  rule-translate.cpp
  RuleMatcher.cpp
  x86-instr.cpp
  x86-parse.cpp
)

# 指定库的类型为动态库
add_library(${LIB_NAME} SHARED ${SRCS})

# 包含当前目录和相关的头文件路径
target_include_directories(${LIB_NAME} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../
  ${CMAKE_CURRENT_SOURCE_DIR}/../../../
)

set (LIBS biscuit fmt::fmt vixl xxhash FEXHeaderUtils)

# 链接FEXCore_Base库，因为PatternDbt目录依赖于该库
target_link_libraries(PatternDbt ${LIBS})

# 添加编译选项和定义
target_compile_definitions(${LIB_NAME} PRIVATE ${DEFINES})
target_compile_options(${LIB_NAME}
  PRIVATE
  -Wall
  -Werror=cast-qual
  -Werror=ignored-qualifiers
  -Werror=implicit-fallthrough
  -Wno-trigraphs
  -ffunction-sections
  -fwrapv
)

# 处理编译器颜色诊断选项
if (GCC_COLOR)
  target_compile_options(${LIB_NAME}
    PRIVATE "-fdiagnostics-color=always")
endif()
if (CLANG_COLOR)
  target_compile_options(${LIB_NAME}
    PRIVATE "-fcolor-diagnostics")
endif()

# 为发布版本设置链接选项
if (CMAKE_BUILD_TYPE MATCHES "RELEASE")
  target_link_options(${LIB_NAME}
    PRIVATE
    "LINKER:--gc-sections"
    "LINKER:--strip-all"
    "LINKER:--as-needed"
  )
endif()

# 安装库到指定路径
install(TARGETS ${LIB_NAME}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  COMPONENT Libraries
)
