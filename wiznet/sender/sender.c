#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pico/stdlib.h"

#include "port_common.h"

#include "wizchip_conf.h"
#include "wizchip_spi.h"
#include "socket.h"

#include <vscp.h>
#include <vscp-class.h>
#include <vscp-type.h>
#include <vscp-firmware-helper.h>
#include <crc.h>

// Uncoment to get debug information from the multicast code
#define _MULTICAST_DEBUG_ 1

// Multicast receive buffer
#define BUFFER_SIZE 2048

/*!
  Default VSCP AES-128 key for VSCP Server - !!!! should only be used on test systems !!!!
*/
#define ENCYPTION_KEY "A4A86F7D7E119BA3F0CD06881E371B98"

/* Clock */
#define PLL_SYS_KHZ (133 * 1000)

/* Buffer */
#define SOCKET_ID             0          // Socket number
#define ETHERNET_BUF_MAX_SIZE (1024 * 2) // Send and receive cache size

static wiz_NetInfo g_net_info = {
  .mac = { 0x00, 0x08, 0xDC, 0x12, 0x34, 0x56 }, // MAC address
  .ip  = { 192, 168, 1, 205 },                   // IP address
  .sn  = { 255, 255, 255, 0 },                   // Subnet Mask
  .gw  = { 192, 168, 1, 1 },                     // Gateway
  .dns = { 8, 8, 8, 8 },                         // DNS server
#if _WIZCHIP_ > W5500
  .lla = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0xdc, 0xff, 0xfe, 0x57, 0x57, 0x25 },  // Link
                                                                                                              // Local
                                                                                                              // Address
  .gua = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },  // Global
                                                                                                              // Unicast
                                                                                                              // Address
  .sn6 = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },  // IPv6
                                                                                                              // Prefix
  .gw6 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },  // Gateway
                                                                                                              // IPv6
                                                                                                              // Address
  .dns6 = { 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88 }, // DNS6
                                                                                                              // server
  .ipmode = NETINFO_STATIC_ALL
#else
  .dhcp = NETINFO_STATIC
#endif
};

// Multicast defines

static uint8_t ethernet_buf[ETHERNET_BUF_MAX_SIZE] = {
  0,
};
static uint8_t s_multicast_ip[4] = { 224, 0, 23, 158 }; // multicast ip address
static uint16_t s_multicast_port = 9598;                // multicast port
static uint8_t s_key[64]         = { 0 };               // Encryption key
static char *s_peventstr         = "0,20,3,,,,0:1:2:3:4:5:6:7:8:9:10:11:12:13:14:15,0,1,35";

/// \tag::timer_example[]
volatile bool timer_fired = false;

///////////////////////////////////////////////////////////////////////////////
// set_clock_khz
//

static void
set_clock_khz(void)
{
  // set a system clock frequency in khz
  set_sys_clock_khz(PLL_SYS_KHZ, true);

  // configure the specified clock
  clock_configure(clk_peri,
                  0,                                                // No glitchless mux
                  CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, // System PLL on AUX mux
                  PLL_SYS_KHZ * 1000,                               // Input frequency
                  PLL_SYS_KHZ * 1000                                // Output (must be same as no divider)
  );
}

///////////////////////////////////////////////////////////////////////////////
// pico_led_init
//
// Perform initialisation
//

int
pico_led_init(void)
{
  gpio_init(19);
  gpio_set_dir(19, GPIO_OUT);
  return PICO_OK;
}

///////////////////////////////////////////////////////////////////////////////
// pico_set_led
//
// Turn the led on or off
//

void
pico_set_led(bool led_on)
{
  // Just set the GPIO on or off
  gpio_put(19, led_on);
}

///////////////////////////////////////////////////////////////////////////////
// sendEvent
//

int32_t
sendEvent(uint8_t sn, const char *pstrev, bool bEncrypt, uint8_t nAlgorithm)
{
  int32_t rv;
  uint16_t buflen          = 0;
  uint8_t buf[BUFFER_SIZE] = { 0 };

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
  buflen = vscp_fwhlp_getFrameSizeFromEventEx(&ex);
  if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_writeEventExToFrame(buf, sizeof(buf), 0, &ex))) {
    fprintf(stderr, "Error writing event to frame. rv=%d\n", rv);
    return VSCP_ERROR_SUCCESS;
  }

#ifdef _MULTICAST_DEBUG_
  printf("Frame size: %d\n", buflen);
  printf("Frame:\n");
  for (int i = 0; i < buflen; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
#endif

  // Encrypt frame as needed
  if (bEncrypt) {

    uint8_t newlen       = 0;
    uint8_t encbuf[1024] = { 0 };

    if (0 == (newlen = vscp_fwhlp_encryptFrame(encbuf, buf, buflen, s_key, NULL, nAlgorithm))) {
      fprintf(stderr, "Error encrypting frame. newlen = %d\n", newlen);
      return VSCP_ERROR_SUCCESS;
    }

    memcpy(buf, encbuf, newlen);
    buf[0] = (buf[0] & 0xF0) | (VSCP_HLO_ENCRYPTION_AES128 & 0x0F); // Set encryption type
    // Set the new length (may be padded to be modulo 16 + 1)
    buflen = newlen;

    if (1) {
      printf("Encrypted frame:\n");
      for (int i = 0; i < buflen; i++) {
        printf("%02x ", buf[i]);
      }
      printf("\nNew length: %d\n", buflen);
    }
  } // encrypted frame

  if ((rv = sendto(SOCKET_ID, buf, buflen, s_multicast_ip, s_multicast_port)) < 0) {
    switch (rv) {
      case SOCKERR_SOCKNUM: // Invalid socket number
        fprintf(stderr, "send event: Invalid socket number\n");
        break;
      case SOCKERR_SOCKMODE: // Invalid operation in the socket
        fprintf(stderr, "send event: Invalid operation in the socket\n");
        break;
      case SOCKERR_SOCKSTATUS: // Invalid socket status for socket operation
        fprintf(stderr, "send event: Invalid socket status for socket operation\n");
        break;
      case SOCKERR_DATALEN: // zero data length
        fprintf(stderr, "send event: Zero data length\n");
        break;
      case SOCKERR_IPINVALID: // Wrong server IP address
        fprintf(stderr, "send event: Wrong server IP address\n");
        break;
      case SOCKERR_PORTZERO: // Server port zero
        fprintf(stderr, "send event: Server port zero\n");
        break;
      case SOCKERR_SOCKCLOSED: // Socket unexpectedly closed
        fprintf(stderr, "send event: Socket unexpectedly closed\n");
        break;
      case SOCKERR_TIMEOUT: // Timeout occurred
        fprintf(stderr, "send event: Timeout occurred\n");
        break;
      case SOCK_BUSY: // Socket is busy.
        fprintf(stderr, "send event: Socket is busy\n");
        break;
    }

    return VSCP_ERROR_ERROR;
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// mcast_recv
//

int32_t
mcast_recv(uint8_t sn, uint8_t *buf, uint8_t *multicast_ip, uint16_t multicast_port)
{
  int32_t rv;
  uint16_t buflen, port = 3000;
  uint8_t destip[4];
  uint16_t destport;
  uint8_t reg;
#if 1
  // 20231019 taylor
  uint8_t addr_len;
#endif

  switch ((reg = getSn_SR(sn))) {

    //------------------------------------------------------
    case SOCK_UDP:
      if ((buflen = getSn_RX_RSR(sn)) > 0) {
        if (buflen > BUFFER_SIZE) {
          buflen = BUFFER_SIZE;
        }
#if 1
        // 20231019 taylor//teddy 240122
#if ((_WIZCHIP_ == 6100) || (_WIZCHIP_ == 6300))
        rv = recvfrom(sn, buf, buflen, destip, (uint16_t *) &destport, &addr_len);
#else
        rv = recvfrom(sn, buf, buflen, destip, (uint16_t *) &destport);
#endif
#else
        rv = recvfrom(sn, buf, size, destip, (uint16_t *) &destport);
#endif
        if (rv <= 0) {
#ifdef _MULTICAST_DEBUG_
          printf("%d: recvfrom error. %ld\r\n", sn, rv);
#endif
          return rv;
        }
        buflen = (uint16_t) rv;
#ifdef _MULTICAST_DEBUG_
        printf("\n------------------------------------------------------------------------\n");
        printf("VSCP UDP coding byte: %02X ", buf[0]);
        switch ((buf[0] & 0x0f)) {

          case VSCP_ENCRYPTION_NONE:
            printf("Unencrypted");
            break;

          case VSCP_ENCRYPTION_AES128:
            printf("Encrypted AES-128");
            break;

          case VSCP_ENCRYPTION_AES192:
            printf("Encrypted AES-192");
            break;

          case VSCP_ENCRYPTION_AES256:
            printf("Encrypted AES-256");
            break;

          default:
            printf("VSCP UDP coding byte :%02X ", buf[1]);
            break;
        }
        printf("\nrecv size: %d\n", buflen);
        for (int i = 0; i < buflen; i++) {
          if (i % 8 == 0) {
            printf("\n");
          }
          printf("%02X ", buf[i]);
        }
        printf("\n");
#endif
        // Decrypt frame if needed
        if (buf[0] & 0x0F) {

          uint8_t encbuf[BUFFER_SIZE] = { 0 };
          if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_decryptFrame(encbuf,
                                                                  buf,
                                                                  buflen - 16,
                                                                  s_key,
                                                                  buf + buflen - 16,
                                                                  VSCP_ENCRYPTION_FROM_TYPE_BYTE))) {
            fprintf(stderr, "Error decrypting frame.\n");
            return rv;
          }

          // Copy decrypted frame back to buffer
          memcpy(buf, encbuf, buflen);
        } // encrypted frame

        vscpEventEx ex;
        memset(&ex, 0, sizeof(ex));
        if (VSCP_ERROR_SUCCESS != (rv = vscp_fwhlp_getEventExFromFrame(&ex, buf, buflen))) {
          fprintf(stderr, "Error reading event from frame. rv=%d\n", rv);
          return rv;
        }

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

        if ((ex.vscp_class == VSCP_CLASS1_CONTROL) && (ex.vscp_type == VSCP_TYPE_CONTROL_TURNON)) {

          printf("%d:Turn ON\n", sn);
          pico_set_led(true); // Turn on LED

          // Send confirmation
          vscpEventEx reply;
          memset(&reply, 0, sizeof(reply));
          reply.head       = 0x00;
          reply.vscp_class = VSCP_CLASS1_INFORMATION;
          reply.vscp_type  = VSCP_TYPE_INFORMATION_ON;
          reply.sizeData   = 3;
          reply.data[0]    = 0x00; // index
          reply.data[1]    = 0x01; // zone
          reply.data[2]    = 0x23; // subzone

          rv = sendto(sn, buf, buflen, destip, destport, 4);
          printf("-------------------------> Sendto: rv=%d", rv);
        }
        else if ((ex.vscp_class == VSCP_CLASS1_CONTROL) && (ex.vscp_type == VSCP_TYPE_CONTROL_TURNOFF)) {

          printf("%d:Turn OFF\n", sn);
          pico_set_led(false); // Turn off LED

          // Send confirmation
          vscpEventEx reply;
          memset(&reply, 0, sizeof(reply));
          reply.head       = 0x00;
          reply.vscp_class = VSCP_CLASS1_INFORMATION;
          reply.vscp_type  = VSCP_TYPE_INFORMATION_OFF;
          reply.sizeData   = 3;
          reply.data[0]    = 0x00; // index
          reply.data[1]    = 0x01; // zone
          reply.data[2]    = 0x23; // subzone
        }
      } // Datagram
      break;

    //------------------------------------------------------
    case SOCK_CLOSED:
#ifdef _MULTICAST_DEBUG_
      printf("%d:Multicast Recv start\n", sn);
#endif
      setSn_DIPR(sn, multicast_ip);
      setSn_DPORT(sn, multicast_port);
      if ((rv = socket(sn, Sn_MR_UDP, port, Sn_MR_MULTI)) != sn) {
        return rv;
      }
#ifdef _MULTICAST_DEBUG_
      printf("%d:Opened, UDP Multicast Socket\n", sn);
      printf("%d:Multicast Group IP - %d.%d.%d.%d\n",
             sn,
             multicast_ip[0],
             multicast_ip[1],
             multicast_ip[2],
             multicast_ip[3]);
      printf("%d:Multicast Group Port - %d\n", sn, multicast_port);
#endif
      break;
  }
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// alarm_callback
//

int64_t
alarm_callback(alarm_id_t id, __unused void *user_data)
{
  printf("Timer %d fired!\n", (int) id);
  timer_fired = true;
  // Can return a value here in us to fire in the future
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
// repeating_timer_callback
//

bool
repeating_timer_callback(__unused struct repeating_timer *t)
{
  printf("Repeat at %lld\n", time_us_64());
  sendEvent(SOCKET_ID, s_peventstr, true, VSCP_ENCRYPTION_AES128);

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// main
//

int
main()
{
  set_clock_khz();

  /*mcu init*/
  stdio_init_all(); // Initialize the main control peripheral.
  wizchip_spi_initialize();
  wizchip_cris_initialize();
  wizchip_reset();
  wizchip_initialize(); // spi initialization
  wizchip_check();

  network_initialize(g_net_info);

  // Set default key (obviously not safe and should not be used in production)
  vscp_fwhlp_hex2bin(s_key, 32, VSCP_DEFAULT_KEY16);

  // Initialize the CRC
  crcInit();

  print_network_information(g_net_info); // Read back the configuration information and print it

  pico_led_init(); // Initialize the LED
  pico_set_led(false);

  // Call alarm_callback in 2 seconds
  add_alarm_in_ms(2000, alarm_callback, NULL, false);

  // Create a repeating timer that calls repeating_timer_callback.
  // If the delay is > 0 then this is the delay between the previous callback ending and the next starting.
  // If the delay is negative (see below) then the next call to the callback will be exactly 500ms after the
  // start of the call to the last callback
  struct repeating_timer timer;
  add_repeating_timer_ms(5000, repeating_timer_callback, NULL, &timer);

  while (true) {
    // Multicast receive test
    mcast_recv(SOCKET_ID, ethernet_buf, s_multicast_ip, s_multicast_port);
  }
}
