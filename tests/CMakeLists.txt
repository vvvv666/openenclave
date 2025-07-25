# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(${PROJECT_SOURCE_DIR}/cmake/get_testcase_name.cmake)

option(ENABLE_FULL_LIBCXX_TESTS
       "Build all libcxx tests and include in test list" OFF)
if (ENABLE_FULL_LIBCXX_TESTS)
  message("ENABLE_FULL_LIBCXX_TESTS set - building all libcxx tests")
else ()
  message("ENABLE_FULL_LIBCXX_TESTS not set - building some libcxx tests")
endif ()

option(ENABLE_FULL_STRESS_TESTS
       "Build all stress tests and include in test list" OFF)
if (ENABLE_FULL_STRESS_TESTS)
  message("ENABLE_FULL_STRESS_TESTS set - building all stress tests")
else ()
  message("ENABLE_FULL_STRESS_TESTS not set - building some stress tests")
endif ()

option(LVI_MITIGATION_SKIP_TESTS "Skip all tests with LVI mitigation" OFF)
if (LVI_MITIGATION MATCHES ControlFlow AND LVI_MITIGATION_SKIP_TESTS)
  message("LVI_MITIGATION_SKIP_TESTS set - skip all tests with LVI mitigation")
endif ()

if (OE_SGX AND UNIX)
  option(ENABLE_ZERO_BASE_TESTS
         "Build 0-base enclave tests and include in test list" ON)
  if (ENABLE_ZERO_BASE_TESTS)
    message("ENABLE_ZERO_BASE_TESTS set - building all 0-base enclave tests")
  else ()
    message(
      "ENABLE_ZERO_BASE_TESTS not set - not building 0-base enclave tests")
  endif ()
endif ()

option(ENABLE_SYMCRYPT_OPENSSL_TESTS
       "Test OpenSSL with SymCrypt engine/provider" ON)
if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
  message(
    "ENABLE_SYMCRYPT_OPENSSL_TESTS set - test OpenSSL with both default settings and SymCrypt engine/provider"
  )
else ()
  message(
    "ENABLE_SYMCRYPT_OPENSSL_TESTS not set - test OpenSSL with only default settings"
  )
endif ()

# Define the `OE_SGX` macro used by the oeedger8r on the SGX build.
if (OE_SGX)
  set(DEFINE_OE_SGX "-DOE_SGX")
endif ()

if (CODE_COVERAGE)
  set(DEFINE_OE_CODE_COVERAGE "-DOE_CODE_COVERAGE")
else ()
  set(DEFINE_OE_CODE_COVERAGE "")
endif ()

if (UNIX)
  # On Linux prefer python3 since python may not be available.
  find_program(PYTHON NAMES python3 python)
else ()
  # On Windows and other systems, use the available python executable.
  set(PYTHON "python")
endif ()

# Disable because this test would fail with code coverage
if (NOT CODE_COVERAGE)
  add_subdirectory(log)
endif ()

add_subdirectory(mem)
add_subdirectory(safecrt)
add_subdirectory(safemath)
add_subdirectory(str)
add_subdirectory(logging)
add_subdirectory(tools)

if (WIN32)
  add_subdirectory(win_paths)
endif ()

if (OE_SGX)
  # Include newly added SGX-specific tests
  # The task to restructure existing tests is tracked
  # in https://github.com/openenclave/openenclave/issues/4281
  add_subdirectory(sgx)
endif ()

if (OE_SGX)
  add_subdirectory(debugger)
  add_subdirectory(host_verify)
  add_subdirectory(invalid_image)
  add_subdirectory(config_id)
  add_subdirectory(switchless)
  add_subdirectory(switchless_atexit_calls)
  add_subdirectory(switchless_threads)
  add_subdirectory(switchless_nestedcalls)
  add_subdirectory(switchless_worksleep)
  add_subdirectory(switchless_one_tcs)

  if (COMPILER_SUPPORTS_SNMALLOC)
    if (NOT USE_SNMALLOC)
      # Do not build that test if we are already using snmalloc for all other tests
      add_subdirectory(snmalloc)
    endif ()
  else ()
    message("The C++ compiler cannot compile snmalloc. Skipping snmalloc test.")
  endif ()

  if (USE_DEBUG_MALLOC)
    add_subdirectory(debug_malloc)
  endif ()
endif ()

if (UNIX
    OR ADD_WINDOWS_ENCLAVE_TESTS
    OR USE_CLANGW)
  if (OE_SGX)
    if (BUILD_ENCLAVES)
      # Disable the memory test for the scenario of building the enclave in Linux and running
      # it on Windows because of the mismatch on the enclave heap size configuration.
      # Also disable the memory test with snmalloc for now because it calls dlmallinfo
      if (NOT USE_SNMALLOC)
        add_subdirectory(memory)
      endif ()
      # Disable tls_e2e on RHEL. For some reasons it may hang on RHEL.
      # https://github.com/openenclave/openenclave/issues/3508
      find_file(REDHAT_FOUND redhat-release redhat-release.conf PATHS /etc)
      if (NOT REDHAT_FOUND)
        add_subdirectory(tls_e2e)
      endif ()
    endif ()

    add_subdirectory(abi)
    add_subdirectory(abortStatus)
    add_subdirectory(argv)
    add_subdirectory(atexit)
    add_subdirectory(attestation_cert_apis)
    add_subdirectory(attestation_plugin)
    add_subdirectory(attestation_plugin_cert)
    add_subdirectory(backtrace)
    add_subdirectory(bigmalloc)
    add_subdirectory(child_thread)
    add_subdirectory(cppException)
    add_subdirectory(crypto_crls_cert_chains)
    add_subdirectory(custom_claims)
    add_subdirectory(debug-mode)
    add_subdirectory(ecall)
    add_subdirectory(ecall_conflict)
    add_subdirectory(ecall_ocall)
    add_subdirectory(echo)
    add_subdirectory(enclaveparam)
    add_subdirectory(file)
    add_subdirectory(getenclave)
    add_subdirectory(ocall)
    add_subdirectory(libcxx)
    add_subdirectory(libcxxrt)
    add_subdirectory(libunwind)
    add_subdirectory(mbed)
    add_subdirectory(mman)
    add_subdirectory(module_loading)
    add_subdirectory(ocall-create)
    add_subdirectory(oeedger8r)
    add_subdirectory(pf_gp_exceptions)
    add_subdirectory(print)
    add_subdirectory(props)
    add_subdirectory(qeidentity)
    add_subdirectory(report)
    add_subdirectory(SampleApp)
    add_subdirectory(SampleAppCRT)
    add_subdirectory(sealKey)
    # Diabled due to TDX QvE verification error
    # add_subdirectory(secure_verify)
    # add_subdirectory(intel_qve_thread_test)
    add_subdirectory(sim-mode)
    add_subdirectory(stdc)
    add_subdirectory(stdcxx)
    add_subdirectory(syscall)
    add_subdirectory(thread)
    add_subdirectory(threadcxx)
    add_subdirectory(thread_local)
    add_subdirectory(thread_local_alignment)
    add_subdirectory(thread_local_large)
    add_subdirectory(thread_local_no_tdata)
    add_subdirectory(VectorException)
    add_subdirectory(stack_overflow_exception)
    add_subdirectory(stack_smashing_protector)
    add_subdirectory(stress)

    # The tests in create-rapid fail when enabling code coverage analysis.
    # The failure happens if the first enclave process terminates, the
    # host fs that libgcov requires in the subsequent enclave processes
    # can no longer be used.
    if (NOT CODE_COVERAGE)
      add_subdirectory(create-rapid)
    endif ()

    if (WITH_EEID)
      add_subdirectory(eeid_plugin)
    endif ()

    if (BUILD_OPENSSL)
      add_subdirectory(symcrypt_engine)
      add_subdirectory(symcrypt_provider)
      add_subdirectory(openssl)
      add_subdirectory(openssl_unsupported)
    endif ()
  endif ()

  add_subdirectory(c99_compliant)
  add_subdirectory(compiler_rt)
  add_subdirectory(create-errors)
  add_subdirectory(crypto)
  add_subdirectory(data_types)
  add_subdirectory(edl_opt_out)
  add_subdirectory(hexdump)
  add_subdirectory(hostcalls)
  add_subdirectory(initializers)
  add_subdirectory(mixed_c_cpp)
  add_subdirectory(pingpong)
  add_subdirectory(pingpong-shared)
endif ()

if (UNIX)
  if (OE_SGX)
    add_subdirectory(cmake_name_conflict)
    # The tests in child_process fail when enabling code coverage analysis.
    # The failure happens if a child process terminates after the parent
    # process does. At this point, the host fs that libgcov requires can no
    # longer be used.
    if (NOT CODE_COVERAGE)
      add_subdirectory(child_process)
    endif ()
    if (ENABLE_ZERO_BASE_TESTS)
      # 0-base enclave creation is currently available only in SGX and UNIX
      # platforms.
      add_subdirectory(sgx_zerobase) # Disabled until PSW update
    endif ()
  endif ()
  add_subdirectory(libc)
endif ()
