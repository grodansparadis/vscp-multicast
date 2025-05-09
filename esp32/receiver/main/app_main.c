#include "esp_err.h"
#include "nvs_flash.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "string.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "sdkconfig.h"

#include <vscp.h>
#include <vscp-firmware-helper.h>
#include <crc.h>

#include "credentials.h" // File containing wifi credentials

const static char *TAG = "Multicast";

#define BUFFER_SIZE 1024

static uint8_t s_key[64]      = { 0 };          // Encryption key
static char *s_multicast_ip   = "224.0.23.158"; // Default address
static short s_multicast_port = 9598;           // Default port

///////////////////////////////////////////////////////////////////////////////
// wifi_event_handler
//

void
wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    esp_wifi_connect();
  }
  else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
    ESP_LOGI(TAG, "Disconnected. Reconnecting...");
    esp_wifi_connect();
  }
  else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
  }
}

///////////////////////////////////////////////////////////////////////////////
// init_wifi
//

void
init_wifi(void)
{
  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  // Initialize the TCP/IP stack
  ESP_ERROR_CHECK(esp_netif_init());

  // Create the default event loop
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  // Create a default Wi-Fi station
  esp_netif_create_default_wifi_sta();

  // Initialize the Wi-Fi driver
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // Register event handlers
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

  // Configure Wi-Fi connection
  wifi_config_t wifi_config = {
        .sta = {
            .ssid = CREDENTIALS_SSID,       // Replace with your Wi-Fi SSID
            .password = CREDENTIALS_PASSWORD // Replace with your Wi-Fi password
        },
    };
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));

  // Start Wi-Fi
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "Wi-Fi initialization complete.");
}

///////////////////////////////////////////////////////////////////////////////
// sendEvent
//
// socket - Socket to send event on
// pstrev - VSCP event on string form to send
// bEncrypt - true if the event should be encrypted with the set key
// nAlgorithm - Encryption algorithm to use (vscp.h)
//

int32_t
sendEvent(int sock, const char *pstrev, bool bEncrypt, uint8_t nAlgorithm)
{
  int32_t rv;
  uint16_t len             = 0;
  uint8_t buf[BUFFER_SIZE] = { 0 };
  struct sockaddr_in multicast_addr;
  unsigned char multicast_ttl = 10;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    ESP_LOGE(TAG, "socket() failed");
    exit(1);
  }

  if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &multicast_ttl, sizeof(multicast_ttl))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(s_multicast_ip);
  multicast_addr.sin_port        = htons(s_multicast_port);

  vscpEventEx ex;
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_parseEventEx(&ex, pstrev))) {
    fprintf(stderr, "Error parsing event string\n");
    return VSCP_ERROR_SUCCESS;
  }

#ifdef _MULTICAST_DEBUG_
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
#endif

  // Calculate needed buffer size
  len = vscp_fwhlp_getFrameSizeFromEventEx(&ex);
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_writeEventExToFrame(buf, sizeof(buf), 0, &ex))) {
    fprintf(stderr, "Error writing event to frame. rv=%u\n", (unsigned) rv);
    return VSCP_ERROR_SUCCESS;
  }

#ifdef _MULTICAST_DEBUG_
  printf("Frame size: %d\n", len);
  printf("Frame:\n");
  for (int i = 0; i < len; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
#endif

  // Encrypt frame as needed
  if (bEncrypt) {

    uint8_t newlen       = 0;
    uint8_t encbuf[1024] = { 0 };

    if (0 == (newlen = vscp_fwhlp_encryptFrame(encbuf, buf, len, s_key, NULL, nAlgorithm))) {
      fprintf(stderr, "Error encrypting frame. newlen = %d\n", newlen);
      return VSCP_ERROR_SUCCESS;
    }

    memcpy(buf, encbuf, newlen);
    buf[0] = (buf[0] & 0xF0) | (VSCP_HLO_ENCRYPTION_AES128 & 0x0F); // Set encryption type
    // Set the new length (may be padded to be modulo 16 + 1)
    len = newlen;

    if (1) {
      printf("Encrypted frame:\n");
      for (int i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
      }
      printf("\nNew length: %d\n", len);
    }
  } // encrypted frame

  ssize_t nsent;
  if ((sendto(sock, buf, len, 0, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) != len) {
    fprintf(stderr, "send event: Failed %d\n", errno);
    return VSCP_ERROR_ERROR;
  }
  // if ((nsent = sendto(sock, buf, len, s_multicast_ip, s_multicast_port)) < len) {
  //   fprintf(stderr, "send event: Failed %d\n", errno);
  //   return VSCP_ERROR_ERROR;
  // }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// handle_vscp_event
//

void
handle_vscp_event(uint8_t *buf, uint16_t len)
{
  int rv;
  bool bVerbose = false;

  if (bVerbose) {
    printf("Buf: ");
    for (int i = 0; i < len; i++) {
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
        vscp_fwhlp_decryptFrame(encbuf, buf, len - 16, s_key, buf + len - 16, VSCP_ENCRYPTION_FROM_TYPE_BYTE)) {
      fprintf(stderr, "Error decrypting frame.\n");
      return;
    }
    if (bVerbose) {
      printf("Decrypted frame:\n");
      printf("Length: %d\n", len);
      for (int i = 0; i < len; i++) {
        printf("%02x ", encbuf[i]);
      }
      printf("\n");
    }

    // Copy decrypted frame back to buffer
    memcpy(buf, encbuf, len);

  } // encrypted

  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_getEventExFromFrame(&ex, buf, len))) {
    fprintf(stderr, "Error reading event from frame. rv=%d\n", rv);
    return;
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
}

///////////////////////////////////////////////////////////////////////////////
// receive_multicast
//

void
receive_multicast(void)
{
  int sock;
  int flag_on = 1;
  struct sockaddr_in multicast_addr;
  char buf[BUFFER_SIZE];
  uint16_t len;
  struct ip_mreq mc_req;
  struct sockaddr_in from_addr;
  unsigned long from_len;

  static char *multicast_ip = "224.0.23.158";
  short multicast_port      = 9598;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    ESP_LOGE(TAG, "socket() failed");
    exit(1);
  }

  if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag_on, sizeof(flag_on))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  multicast_addr.sin_port        = htons(multicast_port);

  if ((bind(sock, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) < 0) {
    ESP_LOGE(TAG, "bind() failed");
    exit(1);
  }

  mc_req.imr_multiaddr.s_addr = inet_addr(multicast_ip);
  mc_req.imr_interface.s_addr = htonl(INADDR_ANY);

  if ((setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &mc_req, sizeof(mc_req))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  while (1) {
    memset(buf, 0, sizeof(buf));
    from_len = sizeof(from_addr);
    memset(&from_addr, 0, from_len);

    ESP_LOGI(TAG, "Wait for message");

    if ((len = recvfrom(sock, buf, BUFFER_SIZE, 0, (struct sockaddr *) &from_addr, &from_len)) < 0) {
      ESP_LOGE(TAG, "recvfrom() failed");
      break;
    }

    ESP_LOGI(TAG, "Message received");
    ESP_LOGI(TAG, "Received %d bytes from %s: ", len, inet_ntoa(from_addr.sin_addr));
    // ESP_LOGI(TAG, "%s", buf);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, buf, len, ESP_LOG_INFO);
  } // while

  /* send a DROP MEMBERSHIP message via setsockopt */
  if ((setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void *) &mc_req, sizeof(mc_req))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }
  close(sock);
}

///////////////////////////////////////////////////////////////////////////////
// send_multicast
//

void
send_multicast()
{
  int sock;
  char *message_to_send = "Hello";
  unsigned int send_len;
  unsigned char multicast_ttl = 10;
  struct sockaddr_in multicast_addr;

  if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    ESP_LOGE(TAG, "socket() failed");
    exit(1);
  }

  if ((setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &multicast_ttl, sizeof(multicast_ttl))) < 0) {
    ESP_LOGE(TAG, "setsockopt() failed");
    exit(1);
  }

  memset(&multicast_addr, 0, sizeof(multicast_addr));
  multicast_addr.sin_family      = AF_INET;
  multicast_addr.sin_addr.s_addr = inet_addr(s_multicast_ip);
  multicast_addr.sin_port        = htons(s_multicast_port);

  send_len = strlen(message_to_send);
  if ((sendto(sock, message_to_send, send_len, 0, (struct sockaddr *) &multicast_addr, sizeof(multicast_addr))) !=
      send_len) {
    ESP_LOGE(TAG, "Error in number of bytes");
    exit(1);
  }
  ESP_LOGI(TAG, "Send done");
  close(sock);
}

///////////////////////////////////////////////////////////////////////////////
// app_main
//

void
app_main(void)
{
  // Set default key (obviously not safe and should not be used in production)
  vscp_fwhlp_hex2bin(s_key, 32, VSCP_DEFAULT_KEY16);

  crcInit();

  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  init_wifi();
  receive_multicast();
}
