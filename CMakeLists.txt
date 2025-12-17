# CMakeList.txt : CMake project for QuicScope, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.10)
project ("QuicScope")

# Options
option(QUICSCOPE_STATIC "Static Build" ON)


if (MSVC)
    add_compile_options(/W4 /permissive-)
    if (QUICSCOPE_STATIC)
          add_compile_options(
            "$<$<CONFIG:Debug>:/MTd>"
            "$<$<CONFIG:RelWithDebInfo>:/MT>"
            "$<$<CONFIG:Release>:/MT>"
            "$<$<CONFIG:MinSizeRel>:/MT>"
        )
        set(QUIC_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(QUIC_BUILD_STATIC ON  CACHE BOOL "" FORCE)
    else()
        set(QUIC_BUILD_SHARED ON  CACHE BOOL "" FORCE)
        set(QUIC_BUILD_STATIC OFF CACHE BOOL "" FORCE)
    endif()
endif()

# Add source to this project's executable.
add_executable (QuicScope "QuicScope.cpp" "QuicScope.h" "CLI11.hpp" "json.hpp" "quic.cpp")


if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET QuicScope PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
# msquic
add_subdirectory(msquic EXCLUDE_FROM_ALL)
target_include_directories(QuicScope PRIVATE  ${CMAKE_SOURCE_DIR}/msquic/src/inc)
target_include_directories(QuicScope PRIVATE  ${CMAKE_BINARY_DIR}/msquic/src/inc)
if (QUICSCOPE_STATIC)
    target_link_libraries(QuicScope PRIVATE msquic_static)
else()
    target_link_libraries(QuicScope PRIVATE msquic)
endif()

# nghttp3
set(ENABLE_SHARED_LIB OFF CACHE BOOL "Disable shared lib for nghttp3")
add_subdirectory(nghttp3 EXCLUDE_FROM_ALL)
target_include_directories(QuicScope PRIVATE  ${CMAKE_SOURCE_DIR}/nghttp3/lib/includes)
target_include_directories(QuicScope PRIVATE  ${CMAKE_BINARY_DIR}/nghttp3/lib/includes)
if (QUICSCOPE_STATIC)
    target_link_libraries(QuicScope PRIVATE nghttp3_static)
else()
    target_link_libraries(QuicScope PRIVATE nghttp3)
endif()

# lua
add_subdirectory(lua EXCLUDE_FROM_ALL)
if (QUICSCOPE_STATIC)
    target_link_libraries(QuicScope PRIVATE lua_static)
else()
    target_link_libraries(QuicScope PRIVATE lua)
endif()

target_include_directories(QuicScope PRIVATE  ${CMAKE_SOURCE_DIR}/Lua/lua-5.4.7/include)

