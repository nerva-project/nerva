set(rpc_websocket_sources
  websocket_server.cpp)

set(rpc_websocket_headers
  websocket_server.h)

monero_add_library(rpc_websocket
  ${rpc_websocket_sources}
  ${rpc_websocket_headers})

target_link_libraries(rpc_websocket
  PUBLIC
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_THREAD_LIBRARY})
