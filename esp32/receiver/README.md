# VSCP multicast listner for esp32

This code listens for VSCP multicast events on the network and prints them to the console. It handles all encryptions and decryptions, including AES128, AES192, and AES256 and is by default setup using AES-128 encryption with the standard 128-bit VSCP demo key.


To use create a file credentials.h that contains the following:

```cpp
#define CREDENTIALS_SSID "your_wifi_ssid"
#define CREDENTIALS_PASSWORD "your_wifi_password"
```

## Build
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 build
```
## Flash
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 flash
```
## Monitor
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 monitor
```
## Clean
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 clean
```
## Erase
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 erase
```
## Build and flash
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 build flash
```
## Build, flash and monitor
```bash
idf.py -p /dev/ttyUSB0 -b 115200 -D ESP32_DEVKITC_V4 build flash monitor
```