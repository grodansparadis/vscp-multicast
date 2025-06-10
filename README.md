# vscp-multicast
VSCP multicast examples for Linux and Windows. Should work on MacOS too.

## [sender](./sender/README.md)
This program can be used to send VSCP events on the a multicast address group.
Events can be sent unencrypted or encrypted with AES-128, AES-192 or AES-256.

## [receiver](./reciver/README.md)
Receive VSCP events on a multicast address group. Received events can be encrypted with AES-128, AES-192, AES-256 or be sent unencrypted.

## Build

### Linux
```bash
mkdir build
cd build
cmake ..
make
```
### Windows
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```
### MacOS
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Tools
  * tcpdump -n udp port 9598
  * tcpdump -i eth0 -s0 -vv host 224.0.23.158
  * https://github.com/UltraMessaging/mtools
  * 
