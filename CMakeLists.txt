cmake_policy(SET CMP0074 NEW)   # Makes Doc generation require CMake 3.12
find_package(Doxygen QUIET COMPONENTS dot)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})
if (DOXYGEN_FOUND)
    set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
#    set(STYLING ${CMAKE_CURRENT_SOURCE_DIR}/assets/doxygen-style/doxygen-awesome.css)
    set(PROCESSED_DOXYFILE ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/xml/index.xml)
    set(CODE_INPUT_DIR ${PROJECT_SOURCE_DIR}/src)
    set(BASE_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR})
    set(DOXYGEN_OUTPUT_DIR ${BASE_OUTPUT_DIR}/doxygen)
    set(MAIN_PAGE ${PROJECT_SOURCE_DIR}/README.md)

    set(PALISADE_VERSION ${PALISADE_VERSION})
    configure_file(${DOXYFILE_IN} ${PROCESSED_DOXYFILE} @ONLY)


    ###############################################
    # Doxygen + Sphinx + Breathe
    ###############################################
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
        set(SPHINX_INDEX_FILE_PDF ${SPHINX_BUILD}/OpenFHE_documentation.pdf)

        add_custom_command(OUTPUT ${SPHINX_INDEX_FILE}
            COMMAND
                ${SPHINX_EXECUTABLE} -j 6 -Q -b html
                # Tell Breathe where to find the Doxygen output
                -Dbreathe_projects.OpenFHE=${DOXYGEN_OUTPUT_DIR}/xml
                ${SPHINX_SOURCE} ${SPHINX_BUILD} 2> errors.txt
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/index.rst
                ${DOXYGEN_INDEX_FILE}
            MAIN_DEPENDENCY ${SPHINX_SOURCE}/conf.py
            COMMENT "Generating documentation with Sphinx")

        # Nice named target so we can run the job easily
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
