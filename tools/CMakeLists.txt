CMAKE_MINIMUM_REQUIRED (VERSION 2.8.0)

SET (AGENT_TOOLS
  add_agent.py
  remove_agent.py
  start_agent.py
  stop_agent.py
  heartbeat.py
  update_profile.py
  minig_engine.py)

INSTALL (
  FILES ${AGENT_TOOLS}
  DESTINATION ${PROJECT_DATA_DIR}/tools
  PERMISSIONS  OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
