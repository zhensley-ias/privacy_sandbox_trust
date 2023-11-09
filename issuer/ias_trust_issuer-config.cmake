# Find our dependent libs
if(NOT TARGET ias_trust_util)
    set(ias_trust_util_DIR ${CMAKE_CURRENT_SOURCE_DIR}/util)
    find_package(ias_trust_util REQUIRED)
endif()


set(dep_libs ${ias_trust_util_LIBRARIES})
set(dep_includes ${ias_trust_util_INCLUDE_DIRS})


add_library(ias_trust_issuer)
target_sources(ias_trust_issuer PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/issuer.cc
)
target_include_directories(ias_trust_issuer PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${dep_includes}
)
target_link_libraries(ias_trust_issuer PUBLIC ${dep_libs})

set(ias_trust_issuer_INSTALL_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include)
set(ias_trust_issuer_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include)
set(ias_trust_issuer_LIBRARIES ias_trust_issuer)
