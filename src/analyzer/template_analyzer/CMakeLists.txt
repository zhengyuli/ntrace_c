CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

IF (NOT CMAKE_BUILD_TYPE)
  SET (CMAKE_BUILD_TYPE "Debug" CACHE STRING
    "Choose the type of build, options are: None, Debug, Release, RelWithDebInfo, MinSizeRel." FORCE)
ENDIF (NOT CMAKE_BUILD_TYPE)
MESSAGE ("Set build type to '${CMAKE_BUILD_TYPE}'")

SET (CMAKE_C_FLAGS "-Wall")
SET (CMAKE_C_FLAGS_DEBUG "-Wall -g")
SET (CMAKE_C_FLAGS_RELEASE "-Wall -O3")

SET (CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

SET (ANALYZER_INSTALL_DIR /usr/share/ntrace/proto_analyzers/)

INCLUDE_DIRECTORIES (
  ./)

SET (TEMPLATE_ANALYZER_FILES
  template_analyzer.c)

ADD_LIBRARY (template_analyzer MODULE ${TEMPLATE_ANALYZER_FILES})
TARGET_LINK_LIBRARIES (template_analyzer jansson)

INSTALL (
  TARGETS template_analyzer
  DESTINATION ${ANALYZER_INSTALL_DIR})
