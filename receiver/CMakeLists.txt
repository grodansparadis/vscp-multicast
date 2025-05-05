project(receiver)

# Create the executable
add_executable(${PROJECT_NAME} receiver.c
                      ../third_party/vscp-firmware/common/vscp-firmware-helper.c
                      ../third_party/vscp-firmware/common/vscp-aes.c
                      ../third_party/vscp-firmware/common/crc.c
)

include_directories(
  .
  ..
  ../third_party/vscp-firmware/common/
)

target_link_libraries(${PROJECT_NAME}
    m
)