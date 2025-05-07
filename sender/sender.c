// Multicast sender

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <stdbool.h>
#include <getopt.h>
#include <vscp.h>
#include <vscp-firmware-helper.h>
#include <crc.h>

#pragma comment(lib, "Ws2_32.lib")

#define MULTICAST_GROUP "224.0.23.158" // Multicast group address (VSCP)
#define MULTICAST_PORT  "9598"         // Multicast port

int
main(int argc, char *argv[])
{
  int rv;
  bool bVerbose = false; // True if verbose information should be printed
  bool bEncrypt = false; // True if frame should be encrypted
#ifdef WIN32
  WSADATA wsaData;
  SOCKET sock;
#else
  int sock;
#endif
  struct sockaddr_in multicast_addr;
  char *eventstr = "0,20,3,,,,0:1:2:3:4:5:6:7:8:9:10:11:12:13:14:15,0,1,35";
  // int eventstr_len = strlen(eventstr);
  char *port          = MULTICAST_PORT;         // Default port
  char *address       = MULTICAST_GROUP;        // Default address
  uint8_t typeEncrypt = VSCP_ENCRYPTION_AES128; // Encryption type (default is AES-128)
  uint8_t key[64]     = { 0 };                  // Encryption key

  // Set default key (obviously not safe and should not be used in production)
  vscp_fwhlp_hex2bin(key, 32, VSCP_DEFAULT_KEY16);

#ifdef WIN32
  // Initialize Winsock
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    fprintf(stderr, "WSAStartup failed\n");
    return EXIT_FAILURE;
  }
#endif

  // Define long options
  static struct option long_options[] = { { "port", required_argument, 0, 'p' },
                                          { "address", required_argument, 0, 'a' },
                                          { "event", required_argument, 0, 'e' },
                                          { "encrypt", optional_argument, 0, 'x' },
                                          { "verbose", no_argument, 0, 'v' },
                                          { "help", no_argument, 0, 'h' },
                                          { 0, 0, 0, 0 } };

  int opt;
  int option_index = 0;

  while ((opt = getopt_long(argc, argv, "p:a:e:x::hv", long_options, &option_index)) != -1) {

    switch (opt) {
      case 'p': // Port
        port = optarg;
        break;

      case 'a': // Address
        address = optarg;
        break;

      case 'e': // Event string
        eventstr = optarg;
        break;

      case 'x': { // Encryption key
        if (bVerbose) {
          printf("Encryption is used\n");
        }
        bEncrypt = true;
        if (NULL == optarg) {
          // No argument - we use default AES-128 key
          typeEncrypt = VSCP_ENCRYPTION_AES128;
          if (bVerbose) {
            printf("AES-128 encryption is used with default key\n");
          }
        }
        else {
          uint8_t keylen = strlen(optarg);
          if (bVerbose) {
            printf("Key length: %d\n", keylen);
          }
          if (keylen < 32) {
            fprintf(stderr, "Encryption key length must be 16/24/32 bytes (32/48/64 hex characters)\n");
            exit(EXIT_FAILURE);
          }
          else if (keylen >= 32 && keylen < 48) {
            typeEncrypt = VSCP_ENCRYPTION_AES128;
            vscp_fwhlp_hex2bin(key, 32, optarg);
            if (bVerbose) {
              printf("Using AES128 encryption\n");
            }
          }
          else if (keylen >= 48 && keylen < 64) {
            typeEncrypt = VSCP_ENCRYPTION_AES192;
            vscp_fwhlp_hex2bin(key, 48, optarg);
            if (bVerbose) {
              printf("Using AES192 encryption\n");
            }
          }
          else if (keylen > 32) {
            typeEncrypt = VSCP_ENCRYPTION_AES256;
            vscp_fwhlp_hex2bin(key, 64, optarg);
            if (bVerbose) {
              printf("Using AES256 encryption\n");
            }
          }
        }
      } break;

      case 'v': // Verbose
        bVerbose = true;
        break;

      case 'h': // Help
      case '?':
        fprintf(stderr, "Usage: %s [--port port] [--address address] [--event event] [--encrypt key]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  crcInit();

  vscpEventEx ex;
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_parseEventEx(&ex, eventstr))) {
    fprintf(stderr, "Error parsing event string\n");
    exit(EXIT_FAILURE);
  }

  if (bVerbose) {
    printf("Parsed event:\n");
    printf("=============\n");
    printf("Class: %d\n", ex.vscp_class);
    printf("Type: %d\n", ex.vscp_type);
    printf("Priority: %d\n", ex.head & 0xE0);
    printf("GUID: ");
    for (int i = 0; i < 16; i++) {
      printf("%02x:", ex.GUID[i]);
    }
    printf("\n");
    printf("Data: ");
    for (int i = 0; i < ex.sizeData; i++) {
      printf("%02x:", ex.data[i]);
    }
    printf("\n");
    printf("----------------------------------------------------\n");
    printf("Timestamp: 0x%08lX\n", (long unsigned int) ex.timestamp);
    printf("Obid: 0x%08lX\n", (long unsigned int) ex.obid);
    printf("Head: %d\n", ex.head);
    printf("Year: %d\n", ex.year);
    printf("Month: %d\n", ex.month);
    printf("Day: %d\n", ex.day);
    printf("Hour: %d\n", ex.hour);
    printf("Minute: %d\n", ex.minute);
    printf("Second: %d\n", ex.second);
    printf("----------------------------------------------------\n");
  }

  // Calculate needed buffer size
  uint16_t buflen = vscp_fwhlp_getFrameSizeFromEventEx(&ex);

  uint8_t buf[1024];
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_writeEventExToFrame(buf, sizeof(buf), 0, &ex))) {
    fprintf(stderr, "Error writing event to frame. rv=%d\n", rv);
    exit(EXIT_FAILURE);
  }

  if (bVerbose) {
    printf("Frame size: %zu\n", vscp_fwhlp_getFrameSizeFromEventEx(&ex));
    printf("Frame:\n");
    for (int i = 0; i < buflen; i++) {
      printf("%02x ", buf[i]);
    }
    printf("\n");
  }

  // Encrypt frame as needed
  if (bEncrypt) {

    uint8_t newlen       = 0;
    uint8_t encbuf[1024] = { 0 };

    if (0 == (newlen = vscp_fwhlp_encryptFrame(encbuf, buf, buflen, key, NULL, typeEncrypt))) {
      fprintf(stderr, "Error encrypting frame. newlen = %d\n", newlen);
      exit(EXIT_FAILURE);
    }

    memcpy(buf, encbuf, newlen);
    buf[0] = (buf[0] & 0xF0) | (VSCP_HLO_ENCRYPTION_AES128 & 0x0F); // Set encryption type
    // Set the new length (may be padded to be modulo 16 + 1)
    buflen = newlen;

    if (bVerbose) {
      printf("Encrypted frame:\n");
      for (int i = 0; i < buflen; i++) {
        printf("%02x ", buf[i]);
      }
      printf("\nNew length: %d\n", buflen);
    }
  }

  // Create a UDP socket
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Socket creation failed");
#ifdef WIN32
    WSACleanup();
#endif    
    exit(EXIT_FAILURE);
  }

  // Allow broadcast (for UDP)
  int broadcastPermission = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastPermission, sizeof(broadcastPermission)) < 0) {
    perror("setsockopt failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Set up the multicast address
  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(address);
  multicast_addr.sin_port        = htons(atoi(port));

  // Send the multicast message
  if (sendto(sock, buf, buflen, 0, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr)) < 0) {
    perror("Sendto failed");
#ifdef WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif    
    
    exit(EXIT_FAILURE);
  }

  if (bVerbose) {
    printf("Multicast event sent.\n");
  }

  // Close the socket
#ifdef WIN32
  closesocket(sock);
  WSACleanup();
#else  
  close(sock);
#endif
  return 0;
}