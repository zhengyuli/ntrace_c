CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

SET (WDM_AGENT_CONFIG_FILE  ${WDM_AGENT_CONFIG_DIR}/agent.conf)

# configure a header file to pass some of the CMake settings
# to the source code
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
  log
  3rdParty/http_parser
  ${PROJECT_BINARY_DIR})

SET (AGENT_SOURCE_FILES
  agent.c
  util/util.c
  util/hash.c
  log/log.c
  service.c
  redis-client.c
  checksum.c
  ip-options.c
  ip-packet.c
  tcp-options.c
  tcp-packet.c
  router.c
  protocol/protocol.c
  protocol/default/default-analyzer.c
  protocol/http/http-analyzer.c
  protocol/mysql/mysql-analyzer.c
  3rdParty/http_parser/http_parser.c)

ADD_EXECUTABLE (wdm-agent ${AGENT_SOURCE_FILES})
TARGET_LINK_LIBRARIES (wdm-agent pcap czmq hiredis pthread ini_config z json)
INSTALL (
  TARGETS wdm-agent
  DESTINATION ${WDM_AGENT_BIN_DIR})

ADD_SUBDIRECTORY (log)
