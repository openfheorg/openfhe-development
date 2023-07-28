#
# CMakeLists.txt for CORE library
#

# all files named *.c or */cpp are compiled to form the library
file (GLOB_RECURSE CORE_SRC_FILES CONFIGURE_DEPENDS lib/*.c lib/*.cpp lib/utils/*.cpp)

list(APPEND CORE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
list(APPEND CORE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/lib")
include_directories(${CORE_INCLUDE_DIRS})
set(CORE_INCLUDE_DIRS "${CORE_INCLUDE_DIRS}" CACHE INTERNAL "")


set(CORE_VERSION_MAJOR ${OPENFHE_VERSION_MAJOR})
set(CORE_VERSION_MINOR ${OPENFHE_VERSION_MINOR})
set(CORE_VERSION_PATCH ${OPENFHE_VERSION_PATCH})
set(CORE_VERSION ${CORE_VERSION_MAJOR}.${CORE_VERSION_MINOR}.${CORE_VERSION_PATCH})

add_library(coreobj OBJECT ${CORE_SRC_FILES})
add_dependencies(coreobj third-party)

set_property(TARGET coreobj PROPERTY POSITION_INDEPENDENT_CODE 1)

if ( BUILD_SHARED )
	add_library (OPENFHEcore SHARED $<TARGET_OBJECTS:coreobj>)
	set_property(TARGET OPENFHEcore PROPERTY VERSION ${CORE_VERSION})
	set_property(TARGET OPENFHEcore PROPERTY SOVERSION ${CORE_VERSION_MAJOR})
	set_property(TARGET OPENFHEcore PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS OPENFHEcore
		EXPORT OpenFHETargets
		DESTINATION lib)
endif()


if( BUILD_STATIC )
	add_library (OPENFHEcore_static STATIC $<TARGET_OBJECTS:coreobj>)
	set_property(TARGET OPENFHEcore_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS OPENFHEcore_static
		EXPORT OpenFHETargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/openfhe/core)

add_custom_target( allcore )

if( BUILD_SHARED )
set (CORELIBS PUBLIC OPENFHEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (OPENFHEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allcore OPENFHEcore)
endif()

if( BUILD_STATIC )
set (CORELIBS ${CORELIBS} PUBLIC OPENFHEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (OPENFHEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allcore OPENFHEcore_static)
endif()

if( BUILD_UNITTESTS )
	if( "${NATIVE_SIZE}" EQUAL 32 )
		message("**** core_tests are not linked for NATIVE_SIZE=32")
	else()
		file (GLOB CORE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
	endif()
	set (CORE_TEST_SRC_FILES ${CORE_TEST_SRC_FILES})
	add_executable( core_tests ${CORE_TEST_SRC_FILES} ${UNITTESTMAIN} )
	set_property(TARGET core_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
	target_link_libraries ( core_tests ${CORELIBS} )
	if (NOT ${WITH_OPENMP})
		target_link_libraries ( core_tests PRIVATE Threads::Threads)
	endif()

	add_dependencies( allcore core_tests )

	add_custom_command( OUTPUT runcoretests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/core_tests )
	add_custom_target( testcore DEPENDS core_tests runcoretests )
endif()

set( COREAPPS "" )
if ( BUILD_EXAMPLES )
	file (GLOB CORE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
	foreach (app ${CORE_EXAMPLES_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		if (${exe} STREQUAL "parallel" AND NOT ${WITH_OPENMP})
			message("Skipping ${exe} because WITH_OPENMP=OFF")
			continue()
		endif()
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/core)
		set( COREAPPS ${COREAPPS} ${exe} )
		target_link_libraries ( ${exe} ${CORELIBS} )
	endforeach()

	add_custom_target( allcoreexamples )
	add_dependencies( allcoreexamples ${COREAPPS} )
	add_dependencies( allcore allcoreexamples )
endif()

set( COREEXTRAS "" )
if (BUILD_EXTRAS)
	file (GLOB CORE_EXTRAS_SRC_FILES CONFIGURE_DEPENDS extras/*.cpp)
	foreach (app ${CORE_EXTRAS_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/extras/core)
		set( COREEXTRAS ${COREEXTRAS} ${exe} )
		target_link_libraries ( ${exe} ${CORELIBS} )
	endforeach()

	add_custom_target( allcoreextras )
	add_dependencies( allcoreextras ${COREEXTRAS} )
	add_dependencies( allcore allcoreextras )
endif()

add_custom_command( OUTPUT coreinfocmd COMMAND echo Builds OPENFHEcore and these apps: ${COREAPPS} )
add_custom_target( coreinfo DEPENDS coreinfocmd )

# Collect compile definitions and pass them upward
if ( BUILD_SHARED )
	get_target_property(_compile_defs OPENFHEcore COMPILE_DEFINITIONS)
	set(_pal_core_compile_defs ${_compile_defs} PARENT_SCOPE)
endif()

if( BUILD_STATIC )
	get_target_property(_compile_defs_static OPENFHEcore_static COMPILE_DEFINITIONS)
	set(_pal_core_compile_defs_static ${_compile_defs_static} PARENT_SCOPE)
endif()
