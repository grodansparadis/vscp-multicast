// Multicast receiver

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <getopt.h>
#include <vscp.h>
#include <vscp-firmware-helper.h>
#include <crc.h>

#define MULTICAST_GROUP "224.0.23.158" // Multicast group address (VSCP)
#define MULTICAST_PORT  "9598"         // Multicast port
#define BUFFER_SIZE     1024

int
main(int argc, char *argv[])
{
  int rv;
  bool bVerbose = false;
  int sock;
  struct sockaddr_in local_addr;
  struct ip_mreq multicast_request;
  uint8_t buf[BUFFER_SIZE];
  char *port      = MULTICAST_PORT;  // Default port
  char *address   = MULTICAST_GROUP; // Default address
  uint8_t key[64] = { 0 };           // Encryption key

  // Define long options
  static struct option long_options[] = {
    { "port", required_argument, 0, 'p' },    
    { "address", required_argument, 0, 'a' },
    { "decrypt", optional_argument, 0, 'x' }, 
    { "verbose", no_argument, 0, 'v' },
    { "help", no_argument, 0, 'h' },          
    { 0, 0, 0, 0 }
  };

  // Set default key (obviously not safe and should not be used in production)
  vscp_fwhlp_hex2bin(key, 32, VSCP_DEFAULT_KEY16);

  int opt;
  int option_index = 0;

  while ((opt = getopt_long(argc, argv, "p:a:hv", long_options, &option_index)) != -1) {
    switch (opt) {
      case 'p': // Port
        port = optarg;
        break;

      case 'a': // Address
        address = optarg;
        break;

      case 'x': { // Encryption key
        uint8_t keylen = strlen(optarg);
        if (bVerbose) {
          printf("Key length: %d\n", keylen);
        }
        if (keylen < 32) {
          fprintf(stderr, "Encryption key length must be 16/24/32 bytes (32/48/64 hex characters)\n");
          exit(EXIT_FAILURE);
        }
        else if (keylen >= 32 && keylen < 48) {
          vscp_fwhlp_hex2bin(key, 32, optarg);
          if (bVerbose) {
            printf("Using AES128 encryption\n");
          }
        }
        else if (keylen >= 48 && keylen < 64) {
          vscp_fwhlp_hex2bin(key, 48, optarg);
          if (bVerbose) {
            printf("Using AES192 encryption\n");
          }
        }
        else if (keylen > 32) {
          vscp_fwhlp_hex2bin(key, 64, optarg);
          if (bVerbose) {
            printf("Using AES256 encryption\n");
          }
        }
        vscp_fwhlp_hex2bin(key, 32, optarg);
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

  // Create a UDP socket
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Allow multiple sockets to use the same port
  int reuse = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse, sizeof(reuse)) < 0) {
    perror("Setting SO_REUSEADDR failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Bind the socket to the multicast port
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sin_family      = AF_INET;
  local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  local_addr.sin_port        = htons(atoi(port));

  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
    perror("Bind failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Join the multicast group
  multicast_request.imr_multiaddr.s_addr = inet_addr(address);
  multicast_request.imr_interface.s_addr = htonl(INADDR_ANY);

  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &multicast_request, sizeof(multicast_request)) < 0) {
    perror("Adding multicast group failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Receive multicast messages
  printf("Listening for multicast messages on %s:%s...\n", MULTICAST_GROUP, MULTICAST_PORT);
  while (1) {

    int buflen = recvfrom(sock, buf, BUFFER_SIZE, 0, NULL, 0);
    if (buflen < 0) {
      perror("Recvfrom failed");
      break;
    }

    if (bVerbose) {
      printf("Buf: ");
      for (int i = 0; i < buflen; i++) {
        printf("%02x:", buf[i]);
      }
      printf("\n");
    }

    // If encrypted frame decrypt it
    if (buf[0] & 0x0F) {

      if (bVerbose) {
        printf("Encrypted frame detected. Type: %d\n", buf[0] & 0x0F);
      }

      uint8_t encbuf[BUFFER_SIZE] = { 0 };
      if (VSCP_ERROR_SUCCESS !=
          vscp_fwhlp_decryptFrame(encbuf, buf, buflen - 16, key, buf + buflen - 16, VSCP_ENCRYPTION_FROM_TYPE_BYTE)) {
        fprintf(stderr, "Error decrypting frame.\n");
        continue;
      }
      if (bVerbose) {
        printf("Decrypted frame:\n");
        printf("Length: %d\n", buflen);
        for (int i = 0; i < buflen; i++) {
          printf("%02x ", encbuf[i]);
        }
        printf("\n");
      }

      // Copy decrypted frame back to buffer
      memcpy(buf, encbuf, buflen);

    } // encrypted

    vscpEventEx ex;
    memset(&ex, 0, sizeof(ex));
    if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_getEventExFromFrame(&ex, buf, buflen))) {
      fprintf(stderr, "Error reading event from frame. rv=%d\n", rv);
      continue;
    }

    if (bVerbose) {
      printf("Event:\n");
      printf("Head: %d\n", ex.head);
      printf("Class: %d\n", ex.vscp_class);
      printf("Type: %d\n", ex.vscp_type);
      printf("Size: %d\n", ex.sizeData);
      for (int i = 0; i < ex.sizeData; i++) {
        printf("%02x ", ex.data[i]);
      }
      printf("\n");
      printf("----------------------------------------------------\n");
      printf("Timestamp: 0x%08lX\n", (long unsigned int) ex.timestamp);
      printf("Obid: 0x%08lX\n", (long unsigned int) ex.obid);
      printf("Year: %d\n", ex.year);
      printf("Month: %d\n", ex.month);
      printf("Day: %d\n", ex.day);
      printf("Hour: %d\n", ex.hour);
      printf("Minute: %d\n", ex.minute);
      printf("Second: %d\n", ex.second);
      printf("----------------------------------------------------\n");
    }
  } // while

  // Leave the multicast group and close the socket
  setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *) &multicast_request, sizeof(multicast_request));
  close(sock);
  return 0;
}
