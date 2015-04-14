CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

SET (AGENT_TOOLS
  resume.py
  pause.py
  heartbeat.py
  update_profile.py
  packets_statistic.py
  mining_engine.py
  breakdown_receiver.py)

INSTALL (
  FILES ${AGENT_TOOLS}
  DESTINATION ${PROJECT_DATA_DIR}/tools
  PERMISSIONS  OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
