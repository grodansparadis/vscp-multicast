cmake_minimum_required (VERSION 3.5)

project(vscp-multicast)

# Add sub directories
add_subdirectory(sender)
add_subdirectory(receiver)

include_directories(
  .
  ..
  ./third_party/vscp-firmware/common/
)
