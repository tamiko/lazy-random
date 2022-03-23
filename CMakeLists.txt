project(lazy-random)
set(VERSION "0.6")
cmake_minimum_required(VERSION 3.3)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

find_package(Boost COMPONENTS thread program_options system REQUIRED)
find_package(Crypto++ REQUIRED)

add_subdirectory(src)

install(FILES ChangeLog COPYING INSTALL README
  DESTINATION share/doc/lazy-random-${VERSION}
  )
