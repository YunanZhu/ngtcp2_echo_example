# 本 CMakeLists 参考了 lib ngtcp2 里对应位置的 CMakeLists 的写法

add_definitions(-DBUILDING_NGTCP2)

set(ngtcp2_SOURCES
  ngtcp2_pkt.c
  ngtcp2_conv.c
  ngtcp2_str.c
  ngtcp2_vec.c
  ngtcp2_buf.c
  ngtcp2_conn.c
  ngtcp2_mem.c
  ngtcp2_pq.c
  ngtcp2_map.c
  ngtcp2_rob.c
  ngtcp2_ppe.c
  ngtcp2_crypto.c
  ngtcp2_err.c
  ngtcp2_range.c
  ngtcp2_acktr.c
  ngtcp2_rtb.c
  ngtcp2_strm.c
  ngtcp2_idtr.c
  ngtcp2_gaptr.c
  ngtcp2_ringbuf.c
  ngtcp2_log.c
  ngtcp2_qlog.c
  ngtcp2_cid.c
  ngtcp2_ksl.c
  ngtcp2_cc.c
  ngtcp2_bbr.c
  ngtcp2_bbr2.c
  ngtcp2_addr.c
  ngtcp2_path.c
  ngtcp2_pv.c
  ngtcp2_pmtud.c
  ngtcp2_version.c
  ngtcp2_rst.c
  ngtcp2_window_filter.c
  ngtcp2_opl.c
  ngtcp2_balloc.c
  ngtcp2_objalloc.c
)

set(ngtcp2_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/includes"
)

# Shared library
add_library(ngtcp2 SHARED ${ngtcp2_SOURCES})
set_target_properties(ngtcp2 PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
target_include_directories(ngtcp2 PUBLIC ${ngtcp2_INCLUDE_DIRS})


# Static library
add_library(ngtcp2_static STATIC ${ngtcp2_SOURCES})
target_compile_definitions(ngtcp2_static PUBLIC "-DNGTCP2_STATICLIB")
target_include_directories(ngtcp2_static PUBLIC ${ngtcp2_INCLUDE_DIRS})