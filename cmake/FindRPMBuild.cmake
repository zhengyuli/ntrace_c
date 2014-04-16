#
# Authors: zhengyu li <zhengyu_li@gmail.com>
#

FIND_PROGRAM (RPMBUILD
  NAMES rpmbuild
  PATHS /usr/bin /usr/local/bin/)

IF (RPMBUILD)
  GET_FILENAME_COMPONENT (RPMBUILD_PATH ${RPMBUILD} ABSOLUTE)
  MESSAGE (STATUS "Found rpmbuild : ${RPMBUILD_PATH}")
  SET (RPMBUILD_FOUND "YES")
ELSE (RPMBUILD)
  MESSAGE (STATUS "Rpmbuild not found. RPM generation will not be available")
  SET (RPMBUILD_FOUND "NO")
ENDIF (RPMBUILD)
