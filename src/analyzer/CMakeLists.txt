CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

INCLUDE_DIRECTORIES (
  ../
  ./http
  ./mysql
  util
  logger
  ../3rd_party/http_parser)

SET (HTTP_ANALYZER_FILES
  http/http_analyzer.c
  ../3rd_party/http_parser/http_parser.c)

ADD_LIBRARY (http_analyzer SHARED ${HTTP_ANALYZER_FILES})
TARGET_LINK_LIBRARIES (http_analyzer jansson)
INSTALL (
  TARGETS http_analyzer
  DESTINATION ${AGENT_ANALYZER_DIR})

SET (MYSQL_ANALYZER_FILES
  mysql/mysql_analyzer.c)

ADD_LIBRARY (mysql_analyzer SHARED ${MYSQL_ANALYZER_FILES})
TARGET_LINK_LIBRARIES (mysql_analyzer jansson)
INSTALL (
  TARGETS mysql_analyzer
  DESTINATION ${AGENT_ANALYZER_DIR})

INSTALL (
  FILES proto_analyzer_h.h
  RENAME proto_analyzer.h
  DESTINATION ${PROJECT_INCLUDE_DIR}
  PERMISSIONS  OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

INSTALL (
  DIRECTORY template_analyzer
  DESTINATION ${PROJECT_DATA_DIR})

