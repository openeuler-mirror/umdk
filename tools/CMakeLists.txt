add_subdirectory(urma_admin)
add_subdirectory(urma_perftest)
if("${TPS}" STREQUAL "enable")
	add_subdirectory(uvs_admin)
endif()
