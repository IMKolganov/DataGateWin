cmake_minimum_required(VERSION 3.22)
project(engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

add_executable(engine
        src/main.cpp
        src/VpnClient.cpp
        src/DnsProxy.cpp
        engine.rc
)

# Make sure your own sources also see these defines.
target_compile_definitions(engine PRIVATE
        _WIN32_WINNT=0x0A00
)

# ---- Dependencies from vcpkg ----
find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(jsoncpp CONFIG REQUIRED)
find_package(lz4 CONFIG REQUIRED)
find_package(xxHash CONFIG REQUIRED)

# ---- OpenVPN3 source root ----
set(O3_DIR "${CMAKE_CURRENT_LIST_DIR}/../openvpn3")

file(GLOB_RECURSE OPENVPN3_CORE_SOURCES
        "${O3_DIR}/client/*.cpp"
        "${O3_DIR}/openvpn/*.cpp"
)

set(_tmp_sources "")
foreach(_s IN LISTS OPENVPN3_CORE_SOURCES)
    file(TO_CMAKE_PATH "${_s}" _s_norm)
    list(APPEND _tmp_sources "${_s_norm}")
endforeach()
set(OPENVPN3_CORE_SOURCES "${_tmp_sources}")
unset(_tmp_sources)

list(FILTER OPENVPN3_CORE_SOURCES EXCLUDE REGEX ".*/openvpn/ovpnagent/.*")
list(FILTER OPENVPN3_CORE_SOURCES EXCLUDE REGEX ".*/openvpn/omi/.*")

add_library(ovpn3-core STATIC
        ${OPENVPN3_CORE_SOURCES}
)

target_include_directories(ovpn3-core PUBLIC
        "${O3_DIR}"
        "${O3_DIR}/client"
)

# ---- tap-windows.h (header only) ----
set(_vcpkg_inc "")
if (DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    set(_vcpkg_inc "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
endif()

find_path(TAP_HEADERS_DIR
        NAMES tap-windows.h
        PATHS
        "${_vcpkg_inc}"
        "F:/C++/vcpkg/installed/x64-windows/include"
)

if (NOT TAP_HEADERS_DIR)
    message(FATAL_ERROR "tap-windows.h not found. Expected it under vcpkg include.")
endif()

target_include_directories(ovpn3-core PRIVATE
        "${TAP_HEADERS_DIR}"
)

target_compile_definitions(ovpn3-core PUBLIC
        TAP_WIN_COMPONENT_ID=tap0901
        _WIN32_WINNT=0x0A00
        ASIO_STANDALONE
        USE_ASIO
        HAVE_LZ4
        USE_OPENSSL
)

target_link_libraries(ovpn3-core PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt-header-only
        JsonCpp::JsonCpp
        lz4::lz4
        xxHash::xxhash
)

target_link_libraries(ovpn3-core PRIVATE
        ws2_32
        iphlpapi
        crypt32
        wininet
        setupapi
        cfgmgr32
        rpcrt4
        wtsapi32
        fwpuclnt
)

target_link_libraries(engine PRIVATE
        ovpn3-core
        Dbghelp
        Ws2_32
)

if (MSVC)
    foreach(_src IN LISTS OPENVPN3_CORE_SOURCES)
        if (_src MATCHES ".*/client/ovpncli\\.cpp$")
            set_source_files_properties("${_src}" PROPERTIES COMPILE_OPTIONS "/bigobj")
        endif()
    endforeach()
endif()
