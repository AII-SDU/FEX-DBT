add_subdirectory(CommonTools)

if (NOT MINGW_BUILD)
  if (BUILD_FEXCONFIG)
    add_subdirectory(FEXConfig/)
  endif()

  if (NOT TERMUX_BUILD)
    # Disable FEXRootFSFetcher on Termux, it doesn't even work there
    add_subdirectory(FEXRootFSFetcher/)
  endif()

  if (ENABLE_GDB_SYMBOLS)
    add_subdirectory(FEXGDBReader/)
  endif()

  add_subdirectory(FEXGetConfig/)
  add_subdirectory(FEXServer/)
  add_subdirectory(FEXBash/)
  add_subdirectory(CodeSizeValidation/)
  add_subdirectory(LinuxEmulation/)

  add_subdirectory(FEXLoader/)
  add_subdirectory(pidof/)
endif()

if (BUILD_TESTS)
  add_subdirectory(TestHarnessRunner/)
endif()
