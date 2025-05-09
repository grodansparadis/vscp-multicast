set(srcs "app_main.c"
        ${CMAKE_SOURCE_DIR}/../../third_party/vscp-firmware/common/vscp-firmware-helper.c
        ${CMAKE_SOURCE_DIR}/../../third_party/vscp-firmware/common/vscp-aes.c
        ${CMAKE_SOURCE_DIR}/../../third_party/vscp-firmware/common/crc.c    )

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "${include_dirs}")

