CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

INCLUDE_DIRECTORIES (
  ./
  ${PROJECT_SOURCE_DIR}/src/util)

ADD_EXECUTABLE (hash-example
  hash-example.c
  ${PROJECT_SOURCE_DIR}/src/util/hash.c
  ${PROJECT_SOURCE_DIR}/src/util/util.c)

ADD_EXECUTABLE (list-example
  list-example.c)

ADD_EXECUTABLE (hiredis-example
  hiredis-example.c)
TARGET_LINK_LIBRARIES (hiredis-example hiredis)

ADD_EXECUTABLE (proc-name-example
  proc-name-example.c)
