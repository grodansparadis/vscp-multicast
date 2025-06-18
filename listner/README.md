# Receive multicast events

Receive VSCP events on a multicast address group. Received events can be encrypted with AES-128, AES-192, AES-256 or be unencrypted. 

Terminate the program with Ctrl-C.

receive -v --address="224.0.23.158" --port="9598" --decrypt="A4A86F7D7E119BA3F0CD06881E371B98"


## Command line switches

-p, --port
  Port to send the multicast event to. Default is 9598.

-a, --address
  Multicast address. Default is the VSCP multicast address 224.0.23.158

-v --verbose 
  Verbose mode. This will print the event to the console.

-x --decrypt
  Encryption key. Argument is a string holding the key as a hexadecimal 
  string. Default key (if switch is not used) is VSCP_DEFAULT_KEY16 (defined as 
  "A4A86F7D7E119BA3F0CD06881E371B98") defined in vscp.h. This will encrypt the 
  message using the AES-128 algorithm. If the key is 128 bits (16-bytes), AES-192 
  if the key is 192 bits long (24 bytes) or AES-256 if the key is 256 bits (32 bytes) long.

