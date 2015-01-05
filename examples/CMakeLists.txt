CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

INCLUDE_DIRECTORIES (
  ./
  ${PROJECT_SOURCE_DIR}/src/util)

ADD_EXECUTABLE (hash_example
  hash_example.c
  ${PROJECT_SOURCE_DIR}/src/util/hash.c
  ${PROJECT_SOURCE_DIR}/src/util/util.c)

ADD_EXECUTABLE (list_example
  list_example.c)

ADD_EXECUTABLE (hiredis_example
  hiredis_example.c)
TARGET_LINK_LIBRARIES (hiredis_example hiredis)

ADD_EXECUTABLE (proc_name_example
  proc_name_example.c)
