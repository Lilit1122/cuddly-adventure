cmake_minimum_required (VERSION 2.6)
project (dhcp-proxy)	
include_directories (${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/../)

set(SOURCE parser.c dhcp-proxy.c)
add_definitions(-Wall)
add_executable(${PROJECT_NAME} ${SOURCE})

add_library(cjson STATIC IMPORTED )
add_library(netfilter_queue STATIC IMPORTED)
add_library(nfnetlink STATIC  IMPORTED)

set_property(TARGET cjson PROPERTY
             IMPORTED_LOCATION ./lib/libcjson.a ) 
set_property(TARGET netfilter_queue PROPERTY
             IMPORTED_LOCATION ./lib/libnetfilter_queue.a)
set_property(TARGET nfnetlink PROPERTY
             IMPORTED_LOCATION ./lib/libnfnetlink.a)

target_link_libraries(${PROJECT_NAME} cjson m pthread netfilter_queue  nfnetlink) 	
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/dhcp-proxy.conf DESTINATION etc)


	

 
