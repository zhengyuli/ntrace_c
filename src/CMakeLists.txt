CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

SET (AGENT_CONFIG_FILE  ${AGENT_CONFIG_DIR}/agent.conf)
SET (AGENT_PID_FILE  /var/run/${ROOT_PROJECT_LOWER}-agent.pid)
SET (AGENT_RUN_DIR /var/run/${ROOT_PROJECT_LOWER})
SET (AGENT_STATE_CACHE_FILE ${AGENT_RUN_DIR}/agent-state.cache)

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
  3rd-party/http_parser
  ${PROJECT_BINARY_DIR})

SET (AGENT_SOURCE_FILES
  agent.c
  util/util.c
  util/hash.c
  logger/logger.c
  checksum.c
  task-manager.c
  service-manager.c
  raw-packet.c
  ip-options.c
  ip-packet.c
  tcp-options.c
  tcp-packet.c
  protocol/protocol.c
  protocol/default/default-analyzer.c
  protocol/http/http-analyzer.c
  protocol/mysql/mysql-analyzer.c
  3rd-party/http_parser/http_parser.c)

ADD_EXECUTABLE (${ROOT_PROJECT_LOWER}-agent ${AGENT_SOURCE_FILES})
TARGET_LINK_LIBRARIES (${ROOT_PROJECT_LOWER}-agent pcap czmq hiredis pthread ini_config z jansson)
INSTALL (
  TARGETS ${ROOT_PROJECT_LOWER}-agent
  DESTINATION ${AGENT_BIN_DIR})

ADD_SUBDIRECTORY (logger)
