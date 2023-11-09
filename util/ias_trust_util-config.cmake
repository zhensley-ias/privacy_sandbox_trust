# Find our dependent libs
set(BORINGSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/boringssl)
set(BORINGSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps)
find_package(BORINGSSL REQUIRED)
find_package(Threads REQUIRED)

set(spdlog_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/spdlog/build)
find_package(spdlog REQUIRED)

set(dep_libs ${BORINGSSL_LIBRARIES} Threads::Threads spdlog::spdlog)
set(dep_includes ${BORINGSSL_INCLUDE_DIR})


add_library(ias_trust_util)
target_sources(ias_trust_util PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/util.cc
)
target_include_directories(ias_trust_util PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${dep_includes}
)
target_link_libraries(ias_trust_util PUBLIC ${dep_libs})

set(ias_trust_util_INSTALL_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include)
set(ias_trust_util_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include ${dep_includes})
set(ias_trust_util_LIBRARIES ias_trust_util ${dep_libs})
