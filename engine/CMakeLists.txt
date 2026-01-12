cmake_minimum_required(VERSION 3.22)
project(engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(engine
        src/main.cpp
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

# Normalize paths to forward slashes so regex works on Windows
set(_tmp_sources "")
foreach(_s IN LISTS OPENVPN3_CORE_SOURCES)
    file(TO_CMAKE_PATH "${_s}" _s_norm)
    list(APPEND _tmp_sources "${_s_norm}")
endforeach()
set(OPENVPN3_CORE_SOURCES "${_tmp_sources}")
unset(_tmp_sources)

# Exclude desktop-only parts
list(FILTER OPENVPN3_CORE_SOURCES EXCLUDE REGEX ".*/openvpn/ovpnagent/.*")
list(FILTER OPENVPN3_CORE_SOURCES EXCLUDE REGEX ".*/openvpn/omi/.*")

add_library(ovpn3-core STATIC
        ${OPENVPN3_CORE_SOURCES}
)

# Expose headers to consumers (engine)
target_include_directories(ovpn3-core PUBLIC
        "${O3_DIR}"
        "${O3_DIR}/client"
)

# Locate tap-windows.h (required by TunWin)
find_path(TAP_HEADERS_DIR
        NAMES tap-windows.h
        HINTS
        "${O3_DIR}/build/msvc/amd64/vcpkg_installed/x64-windows/include"
        "${O3_DIR}/build"
)

if (NOT TAP_HEADERS_DIR)
    message(FATAL_ERROR "tap-windows.h not found. Expected under ${O3_DIR}/build/msvc/amd64/vcpkg_installed/x64-windows/include")
endif()

target_include_directories(ovpn3-core PRIVATE
        "${TAP_HEADERS_DIR}"
)

# Make consumers inherit the exact same defines (engine includes OpenVPN headers too)
target_compile_definitions(ovpn3-core PUBLIC
        _WIN32_WINNT=0x0A00
        ASIO_STANDALONE
        USE_ASIO
        HAVE_LZ4
        USE_OPENSSL
)

# Link deps as PUBLIC so engine inherits include dirs + proper linkage
target_link_libraries(ovpn3-core PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        fmt::fmt-header-only
        JsonCpp::JsonCpp
        lz4::lz4
        xxHash::xxhash
)

# Windows system libs needed by TunWin / WFP / proxy code
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

target_link_libraries(engine PRIVATE ovpn3-core)

# Helpful for debugging crashes
if (MSVC)
    foreach(_src IN LISTS OPENVPN3_CORE_SOURCES)
        if (_src MATCHES ".*/client/ovpncli\\.cpp$")
            set_source_files_properties("${_src}" PROPERTIES COMPILE_OPTIONS "/bigobj")
        endif()
    endforeach()
endif()
