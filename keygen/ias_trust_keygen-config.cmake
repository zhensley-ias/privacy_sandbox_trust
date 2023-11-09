# Find our dependent libs
if(NOT TARGET ias_trust_util)
    set(ias_trust_util_DIR ${CMAKE_CURRENT_SOURCE_DIR}/util)
    find_package(ias_trust_util REQUIRED)
endif()


set(dep_libs ${ias_trust_util_LIBRARIES})
set(dep_includes ${ias_trust_util_INCLUDE_DIRS})


add_library(ias_trust_keygen)
target_sources(ias_trust_keygen PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/keygen.cc
)
target_include_directories(ias_trust_keygen PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        ${dep_includes}
)
target_link_libraries(ias_trust_keygen PUBLIC ${dep_libs})

set(ias_trust_keygen_INSTALL_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include)
set(ias_trust_keygen_INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/include)
set(ias_trust_keygen_LIBRARIES ias_trust_keygen)
