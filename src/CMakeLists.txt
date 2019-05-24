INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR} ${Crypto++_INCLUDE_DIR})

ADD_EXECUTABLE(lazy-random lazy-random.cpp)

TARGET_LINK_LIBRARIES(lazy-random
  ${Boost_LIBRARIES}
  ${Crypto++_LIBRARY}
  )

INSTALL(TARGETS lazy-random RUNTIME DESTINATION bin)
