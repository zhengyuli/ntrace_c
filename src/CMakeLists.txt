CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

# Macro definitions
IF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  ADD_DEFINITIONS (-DDEBUG_BUILD)
ENDIF ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
#ADD_DEFINITIONS (-DDO_STRICT_CHECK)
ADD_DEFINITIONS (-DHAVE_PF_RING)

SET (AGENT_CONFIG_FILE  ${PROJECT_CONFIG_DIR}/${SUB_PROJECT_LOWER}.conf)
SET (AGENT_PID_FILE ${PROJECT_RUN_DIR}/${ROOT_PROJECT_LOWER}_${SUB_PROJECT_LOWER}.pid)
SET (AGENT_ANALYZER_DIR ${PROJECT_DATA_DIR}/analyzers)
SET (AGENT_DETECTOR_DIR ${PROJECT_DATA_DIR}/detectors)
SET (AGENT_APP_SERVICES_CACHE ${PROJECT_RUN_DIR}/app_services.cache)

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
  logger
  app_service/
  ownership/
  management/
  protocol/
  analyzer/
  proto_detection/
  session_breakdown/
  3rd_party/http_parser/
  ${PROJECT_BINARY_DIR})

SET (AGENT_SOURCE_FILES
  agent.c
  util/util.c
  util/hash.c
  properties.c
  option_parser.c
  signals.c
  logger/log_service.c
  logger/log.c
  startup_info.c
  zmq_hub.c
  task_manager.c
  app_service/app_service.c
  app_service/app_service_manager.c
  app_service/app_service_cache.c
  netdev.c
  management/management_service.c
  ownership/ownership.c
  ownership/ownership_manager.c
  protocol/raw_capture_service.c
  protocol/ip_process_service.c
  protocol/icmp_process_service.c
  protocol/tcp_dispatch_service.c
  protocol/tcp_process_service.c
  protocol/checksum.c
  protocol/raw_packet.c
  protocol/ip_options.c
  protocol/ip_packet.c
  protocol/icmp_packet.c
  protocol/tcp_options.c
  protocol/tcp_packet.c
  analyzer/proto_analyzer.c
  analyzer/default/default_analyzer.c
  3rd_party/http_parser/http_parser.c
  analyzer/http/http_analyzer.c
  analyzer/mysql/mysql_analyzer.c
  session_breakdown/session_breakdown_service.c
  proto_detection/proto_detect_service.c)

ADD_EXECUTABLE (${ROOT_PROJECT_LOWER}_agent ${AGENT_SOURCE_FILES})
TARGET_LINK_LIBRARIES (
  ${ROOT_PROJECT_LOWER}_agent
  pcap czmq pthread ini_config z jansson dl uuid)
INSTALL (
  TARGETS ${ROOT_PROJECT_LOWER}_agent
  DESTINATION ${PROJECT_BIN_DIR})

INSTALL (
  FILES agent_service.init
  RENAME ${ROOT_PROJECT_LOWER}_agent
  DESTINATION /etc/init.d/
  PERMISSIONS  OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)

ADD_SUBDIRECTORY (util)
ADD_SUBDIRECTORY (logger)
ADD_SUBDIRECTORY (analyzer)
