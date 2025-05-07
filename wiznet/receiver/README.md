# How to Test UDP multicast receiver Example

This VSCP multicast received is built for the Wiznet **W55RP20-EVB-Pico** board. You can change board type in the CMakeList.txt file to some other WIZNet boards that are available (See 'WIZnet libraries' in the CMakeLists.txt file).

The program receive VSCP multicast frames on the VSCP assigned multicast group (224.0.23.158) on port 9598. Change as necessary in the source file ( see multicast defines). Also you may need to change the IP address, default gateway etc. ( see _g_net_info_)

A default key for AES-128 is defined which is used all over VSCP for testing. This means that the recived will receive unencrypted frames as well as frames encrypted with AES-128 also using the default key. To use a 192-bit (AES-129) or even a 256-bit (AES-356) key just define it as the hexstring for the key. 

Info about VSCP over multicast is available in the [VSCP specification](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_over_multicast).

Easiest way to build this eaxmple is to use Visaul Studio Code with the pico extension installed. Open the folder, compile and run.


## Reference
  * [Application Note UDP_multicast_receiver Example](https://docs.wiznet.io/img/application_notes/PICO-C/UDP_multicast_receiver_EXAMPLE_AN_V100.pdf)
  * [W5100S/W5500+RP2040 Raspberry Pi Pico＜UDP Multicast＞](https://maker.wiznet.io/ronpang/projects/7%2Dw5100s%2Dw5500%2Drp2040%2Draspberry%2Dpi%2Dpicoudp%2Dmulticast/)
  * [W5500 UDP Function](https://docs.wiznet.io/Product/iEthernet/W5500/Application/udp)

