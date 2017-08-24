cmake_minimum_required(VERSION 2.6)

project(ecc_converter)
set(CMAKE_CXX_FLAGS "-g --std=c++11")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Crypto++ REQUIRED)

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CRYPTO++_INCLUDE_DIR}
    )

link_directories(${CMAKE_BINARY_DIR}/lib)

set(PARSER_SOURCE
    ${CMAKE_SOURCE_DIR}/src/main.cpp
    ${CMAKE_SOURCE_DIR}/src/pem-wr.cpp
    ${CMAKE_SOURCE_DIR}/src/pem-rd.cpp
    ${CMAKE_SOURCE_DIR}/src/pem-com.cpp
)

add_executable(${PROJECT_NAME}  ${PARSER_SOURCE})
target_link_libraries(${PROJECT_NAME} 
    ${CRYPTO++_LIBRARIES}
)


#install(DIRECTORY DESTINATION "${QLEMON_DIRECTORY}/lua")
#install (
    #FILES "${PROJECT_SOURCE_DIR}/lua/bastard.lua" 
    #DESTINATION "${QLEMON_DIRECTORY}/lua"
#)

#install(TARGETS ${PROJECT_NAME}
    #RUNTIME DESTINATION "${QLEMON_DIRECTORY}/bin"
#)




