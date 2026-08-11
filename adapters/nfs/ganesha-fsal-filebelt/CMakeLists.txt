# SPDX-License-Identifier: LGPL-3.0-or-later

add_library(fsalfilebelt MODULE
  fsal_filebelt.c
  filebelt_export.c
)

target_compile_definitions(fsalfilebelt PRIVATE FILEBELT_GANESHA_ABI)
target_compile_options(fsalfilebelt PRIVATE
  -Wall -Wextra -Werror -Wconversion -Wformat=2
)
target_include_directories(fsalfilebelt PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(fsalfilebelt
  ganesha_nfsd
  ${SYSTEM_LIBRARIES}
  ${LTTNG_LIBRARIES}
  ${LDFLAG_DISALLOW_UNDEF}
)
set_target_properties(fsalfilebelt PROPERTIES VERSION 6.5.0 SOVERSION 6)
install(TARGETS fsalfilebelt COMPONENT fsal DESTINATION ${FSAL_DESTINATION})
