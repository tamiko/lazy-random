PROJECT (lazy-random)
set (VERSION "0.3")
CMAKE_MINIMUM_REQUIRED (VERSION 2.8) 

######################
## Set up libraries ##
######################

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

FIND_PACKAGE (Boost COMPONENTS thread program_options REQUIRED)
FIND_PACKAGE (Crypto++ REQUIRED)

INCLUDE_DIRECTORIES (${Boost_INCLUDE_DIR} ${Crypto++_INCLUDE_DIR})

SET (LIBS ${LIBS} ${Boost_THREAD_LIBRARY} ${Boost_PROGRAM_OPTIONS_LIBRARY} ${Crypto++_LIBRARY})

###########################
## Process Documentation ##
###########################

SET (DOC_FILES ChangeLog COPYING INSTALL README)
SET (DOC_PATH share/doc/lazy-random-${VERSION})

INSTALL (FILES ${DOC_FILES} DESTINATION ${DOC_PATH})

###################
## Process ./src ##
###################

ADD_SUBDIRECTORY(src)
