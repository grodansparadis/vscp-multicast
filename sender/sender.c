// Multicast sender

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MULTICAST_GROUP "224.0.23.158" // Multicast group address (VSCP)
#define MULTICAST_PORT  9596           // Multicast port

int
main()
{
  int sock;
  struct sockaddr_in multicast_addr;
  char *message   = "Hello, Multicast!";
  int message_len = strlen(message);

  // Create a UDP socket
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("Socket creation failed");
    exit(EXIT_FAILURE);
  }

  // Set up the multicast address
  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
  multicast_addr.sin_port        = htons(MULTICAST_PORT);

  // Send the multicast message
  if (sendto(sock, message, message_len, 0, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr)) < 0) {
    perror("Sendto failed");
    close(sock);
    exit(EXIT_FAILURE);
  }

  printf("Multicast message sent: %s\n", message);

  // Close the socket
  close(sock);
  return 0;
}