include_directories(${Boost_INCLUDE_DIR} ${Crypto++_INCLUDE_DIR})

add_executable(lazy-random lazy-random.cpp)

target_link_libraries(lazy-random
  ${Boost_LIBRARIES}
  ${Crypto++_LIBRARY}
  )

install(TARGETS lazy-random RUNTIME DESTINATION bin)
