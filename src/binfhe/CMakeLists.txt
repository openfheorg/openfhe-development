#
# CMakeLists.txt for BINFHE library
#

# all files named *.cpp are compiled to form the library
file (GLOB BINFHE_SRC_FILES CONFIGURE_DEPENDS lib/*.cpp)

include_directories(${CORE_INCLUDE_DIRS})
list(APPEND BINFHE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
list(APPEND BINFHE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/lib")
include_directories(${BINFHE_INCLUDE_DIRS})

set(BINFHE_VERSION_MAJOR ${OPENFHE_VERSION_MAJOR})
set(BINFHE_VERSION_MINOR ${OPENFHE_VERSION_MINOR})
set(BINFHE_VERSION_PATCH ${OPENFHE_VERSION_PATCH})
set(BINFHE_VERSION ${BINFHE_VERSION_MAJOR}.${BINFHE_VERSION_MINOR}.${BINFHE_VERSION_PATCH})

add_library(binfheobj OBJECT ${BINFHE_SRC_FILES})
set_property(TARGET binfheobj PROPERTY POSITION_INDEPENDENT_CODE 1)

if ( BUILD_SHARED )
	add_dependencies(binfheobj OPENFHEcore)
	add_library (OPENFHEbinfhe SHARED $<TARGET_OBJECTS:binfheobj>)
	set_property(TARGET OPENFHEbinfhe PROPERTY VERSION ${BINFHE_VERSION})
	set_property(TARGET OPENFHEbinfhe PROPERTY SOVERSION ${BINFHE_VERSION_MAJOR})
	set_property(TARGET OPENFHEbinfhe PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS OPENFHEbinfhe
		EXPORT OpenFHETargets
		DESTINATION lib)
endif()

if( BUILD_STATIC )
add_dependencies(binfheobj OPENFHEcore_static)
	add_library (OPENFHEbinfhe_static STATIC $<TARGET_OBJECTS:binfheobj>)
	set_property(TARGET OPENFHEbinfhe_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS OPENFHEbinfhe_static
		EXPORT OpenFHETargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/openfhe/binfhe)

add_custom_target( allbinfhe )

if( BUILD_SHARED )
set (BINFHELIBS PUBLIC OPENFHEbinfhe PUBLIC OPENFHEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (OPENFHEbinfhe PUBLIC OPENFHEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allbinfhe OPENFHEbinfhe  )
endif()

if( BUILD_STATIC )
set (BINFHELIBS ${BINFHELIBS} PUBLIC OPENFHEbinfhe_static PUBLIC OPENFHEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (OPENFHEbinfhe_static PUBLIC OPENFHEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allbinfhe OPENFHEbinfhe_static )
endif()

if( BUILD_UNITTESTS )
	file (GLOB BINFHE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
	add_executable (binfhe_tests ${BINFHE_TEST_SRC_FILES} ${UNITTESTMAIN})
	set_property(TARGET binfhe_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
	target_link_libraries ( binfhe_tests ${BINFHELIBS})
	if (NOT ${WITH_OPENMP})
		target_link_libraries ( binfhe_tests PRIVATE Threads::Threads)
	endif()

	add_dependencies( allbinfhe binfhe_tests )

	add_custom_command( OUTPUT runbinfhetests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/binfhe_tests )
	add_custom_target( testbinfhe DEPENDS binfhe_tests runbinfhetests )
endif()

set (BINFHEAPPS "")
if( BUILD_EXAMPLES)
	file (GLOB BINFHE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
	foreach (app ${BINFHE_EXAMPLES_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/binfhe)
		set( BINFHEAPPS ${BINFHEAPPS} ${exe} )
		target_link_libraries ( ${exe} ${BINFHELIBS} )
	endforeach()

	file (GLOB BINFHE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/pke/*.cpp)
	foreach (app ${BINFHE_EXAMPLES_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/binfhe/pke)
		set( BINFHEAPPS ${BINFHEAPPS} ${exe} )
		target_link_libraries ( ${exe} ${BINFHELIBS} )
	endforeach()

	add_custom_target( allbinfheexamples )
	add_dependencies( allbinfheexamples ${BINFHEAPPS} )
	add_dependencies( allbinfhe allbinfheexamples)
endif()

add_custom_command( OUTPUT binfheinfocmd COMMAND echo Builds OPENFHEbinfhe and these apps: ${BINFHEAPPS} )
add_custom_target( binfheinfo DEPENDS binfheinfocmd )

# Collect compile definitions and pass them upward
if ( BUILD_SHARED )
	get_target_property(_compile_defs OPENFHEbinfhe COMPILE_DEFINITIONS)
	set(_pal_binfhe_compile_defs ${_compile_defs} PARENT_SCOPE)
endif()

if( BUILD_STATIC )
	get_target_property(_compile_defs_static OPENFHEbinfhe_static COMPILE_DEFINITIONS)
	set(_pal_binfhe_compile_defs_static ${_compile_defs_static} PARENT_SCOPE)
endif()
