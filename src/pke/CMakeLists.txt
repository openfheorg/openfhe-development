#
# CMakeLists.txt for PKE library
#

# all files named *-impl.cpp are compiled to form the library
file (GLOB PKE_SRC_FILES CONFIGURE_DEPENDS lib/*-impl.cpp lib/scheme/*/*-impl.cpp)

include_directories(${CORE_INCLUDE_DIRS})
list(APPEND PKE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include")
list(APPEND PKE_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/lib")
include_directories(${PKE_INCLUDE_DIRS})

set(PKE_VERSION_MAJOR ${PALISADE_VERSION_MAJOR})
set(PKE_VERSION_MINOR ${PALISADE_VERSION_MINOR})
set(PKE_VERSION_PATCH ${PALISADE_VERSION_PATCH})
set(PKE_VERSION ${PKE_VERSION_MAJOR}.${PKE_VERSION_MINOR}.${PKE_VERSION_PATCH})

add_library (pkeobj OBJECT ${PKE_SRC_FILES})
set_property(TARGET pkeobj PROPERTY POSITION_INDEPENDENT_CODE 1)

if( BUILD_SHARED )
	add_dependencies(pkeobj PALISADEcore)
	add_library (PALISADEpke SHARED $<TARGET_OBJECTS:pkeobj>)
	set_property(TARGET PALISADEpke PROPERTY VERSION ${PKE_VERSION})
	set_property(TARGET PALISADEpke PROPERTY SOVERSION ${PKE_VERSION_MAJOR})
	set_property(TARGET PALISADEpke PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEpke
		EXPORT PalisadeTargets
		DESTINATION lib)
endif()

if( BUILD_STATIC )
	add_dependencies(pkeobj PALISADEcore_static)
	add_library (PALISADEpke_static STATIC $<TARGET_OBJECTS:pkeobj>)
	set_property(TARGET PALISADEpke_static PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
	install(TARGETS PALISADEpke_static
		EXPORT PalisadeTargets
		DESTINATION lib)
endif()

install(DIRECTORY include/
	DESTINATION include/palisade/pke)

add_custom_target( allpke )

if( BUILD_SHARED )
	set (PKELIBS PUBLIC PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (PALISADEpke PUBLIC PALISADEcore ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allpke PALISADEpke)
endif()

if( BUILD_STATIC )
	set (PKELIBS ${PKELIBS} PUBLIC PALISADEpke_static PUBLIC PALISADEcore_static ${THIRDPARTYLIBS} ${OpenMP_CXX_FLAGS})
	target_link_libraries (PALISADEpke_static PUBLIC PALISADEcore_static ${THIRDPARTYSTATICLIBS} ${OpenMP_CXX_FLAGS})
	add_dependencies( allpke PALISADEpke_static)
endif()

if( BUILD_UNITTESTS )
	file (GLOB PKE_TEST_SRC_FILES CONFIGURE_DEPENDS unittest/*.cpp)
	add_executable (pke_tests ${PKE_TEST_SRC_FILES} ${UNITTESTMAIN})
	set_property(TARGET pke_tests PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/unittest)
	target_link_libraries ( pke_tests ${PKELIBS} )
	if (NOT ${WITH_OPENMP} )
		target_link_libraries ( pke_tests PRIVATE Threads::Threads)
	endif()
	add_dependencies( allpke pke_tests )

	add_custom_command( OUTPUT runpketests WORKING_DIRECTORY ${CMAKE_BINARY_DIR} COMMAND ${CMAKE_BINARY_DIR}/unittest/pke_tests )
	add_custom_target( testpke DEPENDS pke_tests runpketests )
endif()

set(PKEAPPS "")
if ( BUILD_EXAMPLES)
	file (GLOB PKE_EXAMPLES_SRC_FILES CONFIGURE_DEPENDS examples/*.cpp)
	foreach (app ${PKE_EXAMPLES_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		add_executable ( ${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples/pke)
		set( PKEAPPS ${PKEAPPS} ${exe} )
		target_link_libraries ( ${exe} ${PKELIBS} )
	endforeach()

	add_custom_target( allpkeexamples )
	add_dependencies( allpkeexamples ${PKEAPPS} )
	add_dependencies( allpke allpkeexamples )
endif()

set( PKEEXTRAS "" )
if (BUILD_EXTRAS)
	file (GLOB PKE_EXTRAS_SRC_FILES CONFIGURE_DEPENDS extras/*.cpp)
	foreach (app ${PKE_EXTRAS_SRC_FILES})
		get_filename_component ( exe ${app} NAME_WE )
		add_executable (${exe} ${app} )
		set_property(TARGET ${exe} PROPERTY RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/extras/pke)
		set( PKEEXTRAS ${PKEEXTRAS} ${exe} )
		target_link_libraries ( ${exe} ${PKELIBS} )
	endforeach()

	add_custom_target( allpkeextras )
	add_dependencies( allpkeextras ${PKEEXTRAS} )
	add_dependencies( allpke allpkeextras )
endif()

add_custom_command( OUTPUT pkeinfocmd COMMAND echo Builds PALISADEpke and these apps: ${PKEAPPS} )
add_custom_target( pkeinfo DEPENDS pkeinfocmd )
