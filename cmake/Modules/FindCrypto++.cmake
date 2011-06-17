# Try to find Crypto++

INCLUDE(FindPackageHandleStandardArgs)

FIND_PATH(Crypto++_INCLUDE_DIR_SUFFIX++ crypto++/misc.h
  HINTS
  $ENV{CRYPTOPP_DIR}/include
  /usr/include
  /usr/local/include
)

FIND_PATH(Crypto++_INCLUDE_DIR_SUFFIXpp cryptopp/misc.h
  HINTS
  $ENV{CRYPTOPP_DIR}/include
  /usr/include
  /usr/local/include
)

IF(Crypto++_INCLUDE_DIR_SUFFIX++)
  SET(Crypto++_INCLUDE_DIR ${Crypto++_INCLUDE_DIR_SUFFIX++}/crypto++)
ELSE(Crypto++_INCLUDE_DIR_SUFFIX++)
  SET(Crypto++_INCLUDE_DIR ${Crypto++_INCLUDE_DIR_SUFFIXpp}/cryptopp)
ENDIF(Crypto++_INCLUDE_DIR_SUFFIX++)

FIND_LIBRARY(Crypto++_LIBRARY
  NAMES crypto++ cryptopp
  PATHS
  $ENV{CRYPTOPP_DIR}/lib
  PATH_SUFFIXES lib64 lib
)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(Crypto++ DEFAULT_MSG Crypto++_LIBRARY Crypto++_INCLUDE_DIR)

MARK_AS_ADVANCED(
  Crypto++_LIBRARY
  Crypto++_INCLUDE_DIR_SUFFIX++
  Crypto++_INCLUDE_DIR_SUFFIXpp)
