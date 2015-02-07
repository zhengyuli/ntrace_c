CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

# Macro definitions
IF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  ADD_DEFINITIONS (-DDEBUG_BUILD)
ENDIF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
#ADD_DEFINITIONS (-DDO_STRICT_CHECK)
ADD_DEFINITIONS (-DHAVE_PF_RING)

SET (AGENT_CONFIG_FILE  ${PROJECT_CONFIG_DIR}/agent.conf)
SET (AGENT_PID_FILE /var/run/${ROOT_PROJECT_LOWER}_agent.pid)
SET (AGENT_ANALYZER_DIR ${PROJECT_DATA_DIR}/analyzers)
SET (AGENT_APP_SERVICES_CACHE ${PROJECT_RUN_DIR}/application_services.cache)

# Configuration header file
configure_file (
  ${PROJECT_SOURCE_DIR}/src/config.h.in
  ${PROJECT_BINARY_DIR}/config.h)

# Version header file
configure_file (
  ${PROJECT_SOURCE_DIR}/src/version.h.in
  ${PROJECT_BINARY_DIR}/version.h)

INCLUDE_DIRECTORIES (
  ./
  util
  log
  protocol/
  analyzer/
  3rd_party/http_parser/
  ${PROJECT_BINARY_DIR})

SET (AGENT_SOURCE_FILES
  agent.c
  util/util.c
  util/hash.c
  properties.c
  args_parser.c
  signals.c
  log/log_service.c
  log/log.c
  zmq_hub.c
  task_manager.c
  app_service.c
  app_service_manager.c
  management_service.c
  netdev.c
  publish_session_breakdown.c
  raw_capture_service.c
  ip_process_service.c
  icmp_process_service.c
  tcp_process_service.c
  protocol/checksum.c
  protocol/raw_packet.c
  protocol/ip_options.c
  protocol/ip_packet.c
  protocol/icmp_packet.c
  protocol/tcp_options.c
  protocol/tcp_packet.c
  analyzer/proto_analyzer.c
  analyzer/default/default_analyzer.c
  analyzer/http/http_analyzer.c
  3rd_party/http_parser/http_parser.c
  analyzer/mysql/mysql_analyzer.c)

ADD_EXECUTABLE (${ROOT_PROJECT_LOWER}_agent ${AGENT_SOURCE_FILES})
TARGET_LINK_LIBRARIES (${ROOT_PROJECT_LOWER}_agent pcap czmq pthread ini_config z jansson dl uuid)
INSTALL (
  TARGETS ${ROOT_PROJECT_LOWER}_agent
  DESTINATION ${PROJECT_BIN_DIR})

INSTALL (
  FILES agent_service.init
  RENAME ${ROOT_PROJECT_LOWER}_agent
  DESTINATION /etc/init.d/
  PERMISSIONS  OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)

ADD_SUBDIRECTORY (log)
ADD_SUBDIRECTORY (analyzer)
