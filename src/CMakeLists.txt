CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

SET (AGENT_CONFIG_FILE  ${AGENT_CONFIG_DIR}/agent.conf)
SET (AGENT_PID_FILE  /var/run/${ROOT_PROJECT_LOWER}_agent.pid)
SET (AGENT_RUN_DIR /var/run/${ROOT_PROJECT_LOWER})
SET (AGENT_CONTEXT_CACHE_DB ${AGENT_RUN_DIR}/context_cache.json)

# Configuration header file
configure_file (
  ${PROJECT_SOURCE_DIR}/src/config.h.in
  ${PROJECT_BINARY_DIR}/config.h)

INCLUDE_DIRECTORIES (
  ./
  protocol/
  protocol/default
  protocol/http
  protocol/mysql
  util
  logger
  3rd_party/http_parser
  ${PROJECT_BINARY_DIR})

SET (AGENT_SOURCE_FILES
  agent.c
  util/util.c
  util/hash.c
  logger/logger.c
  checksum.c
  task_manager.c
  context_cache.c
  service.c
  service_manager.c
  raw_packet.c
  ip_options.c
  ip_packet.c
  tcp_options.c
  tcp_packet.c
  protocol/protocol.c
  protocol/default/default_analyzer.c
  protocol/http/http_analyzer.c
  protocol/mysql/mysql_analyzer.c
  3rd_party/http_parser/http_parser.c)

ADD_EXECUTABLE (${ROOT_PROJECT_LOWER}_agent ${AGENT_SOURCE_FILES})
TARGET_LINK_LIBRARIES (${ROOT_PROJECT_LOWER}_agent pcap czmq hiredis pthread ini_config z jansson)
INSTALL (
  TARGETS ${ROOT_PROJECT_LOWER}_agent
  DESTINATION ${AGENT_BIN_DIR})

ADD_SUBDIRECTORY (logger)
