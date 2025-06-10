# Send multicast event

This program can be used to send VSCP events on the a multicast address group.
Events can be sent unencrypted or encrypted with AES-128, AES-192 or AES-256.

## example

```bash
sender -v --address="224.0.23.158" --port="9598" --event="0,20,3,0,,0,0:1:2:3:4:5:6:7:8:9:10:11:12:13:14:15,0,1,35" -encrypt="A4A86F7D7E119BA3F0CD06881E371B98"
```

## Command line switches

-p --port
  Port to send the multicast event to. Default is 9598.

-a, --address
  Multicast address. Default is the VSCP multicast address 224.0.23.158.

-e, --event
  Event to send on VSCP string format. Default is CLASS1.CONTROL, ON.

-v --verbose 
  Verbose mode. This will print the event to the console.

-x, --encrypt
  Encrypt the message. If no argument is given the event will be encrypted using
  AES-128 and the key VSCP_DEFAULT_KEY16 (defined as "A4A86F7D7E119BA3F0CD06881E371B98") 
  defined in vscp.h. If an argument is given is should be a hexadecimal string 
  holding the key. The key should be 16, 24 or 32 bytes long (128, 192 or 256 bits). 
  If the key is 128 bits (16-bytes), AES-192 if the key is 192 bits long (24 bytes) 
  or AES-256 if the key is 256 bits (32 bytes) long. The key should be given as a 
  hexadecimal string. 

## Tools
  * [tcpdump](https://www.tcpdump.org/) - A powerful command-line packet analyzer.
  * [mtools](https://github.com/UltraMessaging/mtools)

Monitor multicast traffic on port 9598 

  ```bash
  sudo tcpdump  -s0 -vv host 224.0.23.158
  ```

Listening for multicast events on port 9598:

```bash
  mdump 224.0.23.158 9598
``` 
