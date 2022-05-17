cmake_policy(SET CMP0074 NEW)   # Makes Doc generation require CMake 3.12
find_package(Doxygen QUIET COMPONENTS dot)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})
if (DOXYGEN_FOUND)
    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    set(PROCESSED_DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    set(CODE_INPUT_DIR ${PROJECT_SOURCE_DIR}/src)
    set(BASE_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(MAIN_PAGE ${PROJECT_SOURCE_DIR}/README.md)

    set(OPENFHE_VERSION ${OPENFHE_VERSION})
    configure_file(${DOXYFILE_IN} ${PROCESSED_DOXYFILE} @ONLY)


    ###############################################
    # Doxygen + Sphinx + Breathe
    ###############################################
    set(STYLING ${CMAKE_CURRENT_SOURCE_DIR}/assets/doxygen-style/doxygen-awesome.css)
    set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/xml/index.xml)
    set(DOXYGEN_OUTPUT_DIR ${BASE_OUTPUT_DIR}/doxygen)
    file(MAKE_DIRECTORY ${DOXYGEN_OUTPUT_DIR})
    add_custom_command(OUTPUT ${DOXYGEN_INDEX_FILE}
            COMMAND echo "${PROCESSED_DOXYFILE}"
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
            MAIN_DEPENDENCY ${DOXYFILE_OUT} ${DOXYFILE_IN}
            COMMENT "Generating docs"
            VERBATIM)

    add_custom_target(Doxygen ALL DEPENDS ${DOXYGEN_INDEX_FILE})

    find_package(Sphinx)
    if (Sphinx_FOUND)
        message(STATUS "Sphinx documentation will be built")

        set(SPHINX_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})
        set(SPHINX_BUILD ${BASE_OUTPUT_DIR}/sphinx)
        set(SPHINX_INDEX_FILE ${SPHINX_BUILD}/index.html)
        set(SPHINX_DEBUG_INDEX_FILE ${SPHINX_BUILD}/index.html)
        set(SPHINX_INDEX_FILE_PDF ${SPHINX_BUILD}/OpenFHE_documentation.pdf)

        add_custom_command(OUTPUT ${SPHINX_INDEX_FILE}
            COMMAND
                ${SPHINX_EXECUTABLE} -Q -j 6 -b html
                ${SPHINX_SOURCE} ${SPHINX_BUILD}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/index.rst
            MAIN_DEPENDENCY ${SPHINX_SOURCE}/conf.py
            COMMENT "Generating documentation with Sphinx")

        add_custom_target(Sphinx ALL DEPENDS ${SPHINX_INDEX_FILE})

        include(GNUInstallDirs)
        install(DIRECTORY ${SPHINX_BUILD}
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
        ###############################################
        # Doxygen only
        ###############################################
    else (Sphinx_FOUND)
        message(STATUS "Sphinx was not found. Build documentation with `make Doxygen`")

    endif (Sphinx_FOUND)

else (DOXYGEN_FOUND)
    message(STATUS "Doxygen and dot (from graphviz) need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)
