# Try to find Crypto++

INCLUDE(FindPackageHandleStandardArgs)

FIND_FILE(Crypto++_INCLUDE_DIR NAMES crypto++/misc.h cryptopp/misc.h)
GET_FILENAME_COMPONENT(Crypto++_INCLUDE_DIR ${Crypto++_INCLUDE_DIR} PATH)

FIND_LIBRARY(Crypto++_LIBRARY NAMES crypto++ cryptopp)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(Crypto++ DEFAULT_MSG Crypto++_LIBRARY Crypto++_INCLUDE_DIR)
