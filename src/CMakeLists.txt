CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

SET (AGENT_CONFIG_FILE  ${AGENT_CONFIG_DIR}/agent.conf)
SET (AGENT_PID_FILE  /var/run/${ROOT_PROJECT_LOWER}_agent.pid)
SET (AGENT_RUN_DIR /var/run/${ROOT_PROJECT_LOWER})
SET (AGENT_RUNTIME_CONTEXT_CACHE ${AGENT_RUN_DIR}/runtime_context_cache.json)
SET (AGENT_ANALYZER_DIR ${AGENT_DATA_DIR}/analyzers)

# Configuration header file
configure_file (
  ${PROJECT_SOURCE_DIR}/src/config.h.in
  ${PROJECT_BINARY_DIR}/config.h)

INCLUDE_DIRECTORIES (
  ./
  util
  logger
  protocol/
  analyzer/
  ${PROJECT_BINARY_DIR})

SET (AGENT_SOURCE_FILES
  agent.c
  util/util.c
  util/hash.c
  properties_manager.c
  version.c
  logger/logger.c
  zmq_hub.c
  task_manager.c
  runtime_context.c
  app_service.c
  app_service_manager.c
  raw_packet_service.c
  ip_packet_service.c
  tcp_packet_service.c
  ./protocol/checksum.c
  ./protocol/raw_packet.c
  ./protocol/ip_options.c
  ./protocol/ip_packet.c
  ./protocol/tcp_options.c
  ./protocol/tcp_packet.c
  analyzer/proto_analyzer.c
  analyzer/default/default_analyzer.c)

ADD_EXECUTABLE (${ROOT_PROJECT_LOWER}_agent ${AGENT_SOURCE_FILES})
TARGET_LINK_LIBRARIES (${ROOT_PROJECT_LOWER}_agent pcap czmq hiredis pthread ini_config z jansson dl)
INSTALL (
  TARGETS ${ROOT_PROJECT_LOWER}_agent
  DESTINATION ${AGENT_BIN_DIR})

ADD_SUBDIRECTORY (util)
ADD_SUBDIRECTORY (logger)
ADD_SUBDIRECTORY (analyzer)
