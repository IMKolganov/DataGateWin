cmake_minimum_required(VERSION 3.22)
project(engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(ENGINE_SHOW_INCLUDES "Enable MSVC /showIncludes for debugging include duplication" OFF)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    add_compile_options(/FS)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
            "$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>"
    )
endif()

add_executable(engine
        main.cpp
        AppMain.cpp
        AppMain.h
        engine.rc

        src/ipc/IpcProtocol.h
        src/ipc/IpcServer.cpp
        src/ipc/IpcServer.h

        src/session/SessionController.cpp
        src/session/SessionController.h
        src/session/SessionState.h

        src/vpn/VpnRunner.cpp
        src/vpn/VpnRunner.h
        src/vpn/client/VpnClient.cpp
        src/vpn/client/VpnClient.h

        src/bridge/WssBridgeRunner.cpp
        src/bridge/WssBridgeRunner.h
        src/bridge/client/WssTcpBridge.cpp
        src/bridge/client/WssTcpBridge.h

        src/util/OvpnTransform.cpp
        src/util/OvpnTransform.h
        src/vpn/openvpn_clientapi_fwd.h
)

target_compile_definitions(engine PRIVATE
        _WIN32_WINNT=0x0A00
        NOMINMAX
        WIN32_LEAN_AND_MEAN
)

target_include_directories(engine PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}"
        "${CMAKE_CURRENT_LIST_DIR}/src"
)

if (MSVC)
    set_target_properties(engine PROPERTIES
            COMPILE_PDB_NAME "engine_compile"
            COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pdb/engine"
    )
endif()

if (MSVC AND ENGINE_SHOW_INCLUDES)
    target_compile_options(engine PRIVATE /showIncludes)
endif()

find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(jsoncpp CONFIG REQUIRED)
find_package(lz4 CONFIG REQUIRED)
find_package(xxHash CONFIG REQUIRED)
find_package(Boost REQUIRED)

# Canonicalize OpenVPN3 root path to avoid pragma-once duplication via different paths
set(O3_DIR_RAW "${CMAKE_CURRENT_LIST_DIR}/../openvpn3")
get_filename_component(O3_DIR "${O3_DIR_RAW}" REALPATH)

file(GLOB_RECURSE OPENVPN3_CORE_SOURCES
        "${O3_DIR}/client/*.cpp"
        "${O3_DIR}/openvpn/*.cpp"
)

list(FILTER OPENVPN3_CORE_SOURCES EXCLUDE REGEX ".*/openvpn/ovpnagent/.*")
list(FILTER OPENVPN3_CORE_SOURCES EXCLUDE REGEX ".*/openvpn/omi/.*")

add_library(ovpn3-core STATIC ${OPENVPN3_CORE_SOURCES})

# Expose only the canonical root. Do not add "${O3_DIR}/client".
target_include_directories(ovpn3-core PUBLIC
        "${O3_DIR}"
)

if (MSVC)
    set_target_properties(ovpn3-core PROPERTIES
            COMPILE_PDB_NAME "ovpn3_core_compile"
            COMPILE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/pdb/ovpn3-core"
    )
endif()

if (MSVC AND ENGINE_SHOW_INCLUDES)
    target_compile_options(ovpn3-core PRIVATE /showIncludes)
endif()

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
    message(FATAL_ERROR "tap-windows.h not found")
endif()

target_include_directories(ovpn3-core PRIVATE "${TAP_HEADERS_DIR}")

target_compile_definitions(ovpn3-core PUBLIC
        _WIN32_WINNT=0x0A00
        USE_ASIO
        USE_OPENSSL
        HAVE_LZ4
        NOMINMAX
        WIN32_LEAN_AND_MEAN
)

target_compile_definitions(ovpn3-core PRIVATE
        ASIO_STANDALONE
        TAP_WIN_COMPONENT_ID=tap0901
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
        Boost::boost
)

if (MSVC)
    foreach(_src IN LISTS OPENVPN3_CORE_SOURCES)
        if (_src MATCHES ".*/client/ovpncli\\.cpp$")
            set_source_files_properties("${_src}" PROPERTIES COMPILE_OPTIONS "/bigobj")
        endif()
    endforeach()
endif()
