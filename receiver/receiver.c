// Multicast receiver

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MULTICAST_GROUP "224.0.23.158" // Multicast group address (VSCP)
#define MULTICAST_PORT  9598           // Multicast port
#define BUFFER_SIZE     1024

int
main()
{
  int sock;
  struct sockaddr_in local_addr;
  struct ip_mreq multicast_request;
  char buffer[BUFFER_SIZE];

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
  local_addr.sin_port        = htons(MULTICAST_PORT);

  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0) {
    perror("Bind failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Join the multicast group
  multicast_request.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
  multicast_request.imr_interface.s_addr = htonl(INADDR_ANY);

  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &multicast_request, sizeof(multicast_request)) < 0) {
    perror("Adding multicast group failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  // Receive multicast messages
  printf("Listening for multicast messages on %s:%d...\n", MULTICAST_GROUP, MULTICAST_PORT);
  while (1) {
    int len = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, 0);
    if (len < 0) {
      perror("Recvfrom failed");
      break;
    }
    buffer[len] = '\0';
    printf("Received multicast message: %s\n", buffer);
  }

  // Leave the multicast group and close the socket
  setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *) &multicast_request, sizeof(multicast_request));
  close(sock);
  return 0;
}
