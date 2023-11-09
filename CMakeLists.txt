cmake_minimum_required(VERSION 3.1.0)
project(IAS_Trust)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT TARGET ias_trust_util)
    set(ias_trust_util_DIR ${CMAKE_CURRENT_LIST_DIR}/util)
    find_package(ias_trust_util)
endif()

if(NOT TARGET ias_trust_keygen)
    set(ias_trust_keygen_DIR ${CMAKE_CURRENT_LIST_DIR}/keygen)
    find_package(ias_trust_keygen)
endif()

if(NOT TARGET ias_trust_issuer)
    set(ias_trust_issuer_DIR ${CMAKE_CURRENT_LIST_DIR}/issuer)
    find_package(ias_trust_issuer)
endif()

#if(NOT TARGET ias_trust_redeemer)
#    set(ias_trust_redeemer_DIR ${CMAKE_CURRENT_LIST_DIR}/redeemer)
#    find_package(ias_trust_redeemer)
#endif()


add_executable(ias_trust)
target_sources(ias_trust PUBLIC ias_trust.cc)
target_link_libraries(ias_trust PUBLIC
        ${ias_trust_util_LIBRARIES}
        ${ias_trust_keygen_LIBRARIES}
        ${ias_trust_issuer_LIBRARIES}
)
target_include_directories(ias_trust PUBLIC
        ${ias_trust_util_INCLUDE_DIRS}
        ${ias_trust_keygen_INCLUDE_DIRS}
        ${ias_trust_issuer_INCLUDE_DIRS}
)

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/keys)