#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "port_common.h"

#include "wizchip_conf.h"
#include "wizchip_spi.h"
#include "socket.h"

#include <vscp.h>
#include <vscp-firmware-helper.h>
#include <crc.h>

// Define to get debug information from the multicast code
#define _MULTICAST_DEBUG_

// Multicast receive buffer
#define BUFFER_SIZE 1024

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
  .ip  = { 192, 168, 1, 200 },                   // IP address
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
static uint8_t multicast_ip[4] = { 224, 0, 23, 158 }; // multicast ip address
static uint16_t multicast_port = 9598;                // multicast port
static uint8_t key[64]         = { 0 };               // Encryption key

static void
set_clock_khz(void);

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
#if 1
  // 20231019 taylor
  uint8_t addr_len;
#endif

  switch (getSn_SR(sn)) {

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
                                                                  key,
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
      }
      break;

    case SOCK_CLOSED:
#ifdef _MULTICAST_DEBUG_
      printf("%d:Multicast Recv start\r\n", sn);
#endif
      setSn_DIPR(sn, multicast_ip);
      setSn_DPORT(sn, multicast_port);
      if ((rv = socket(sn, Sn_MR_UDP, port, Sn_MR_MULTI)) != sn) {
        return rv;
      }
#ifdef _MULTICAST_DEBUG_
      printf("%d:Opened, UDP Multicast Socket\r\n", sn);
      printf("%d:Multicast Group IP - %d.%d.%d.%d\r\n",
             sn,
             multicast_ip[0],
             multicast_ip[1],
             multicast_ip[2],
             multicast_ip[3]);
      printf("%d:Multicast Group Port - %d\r\n", sn, multicast_port);
#endif
      break;

    default:
      break;
  }
  return VSCP_ERROR_SUCCESS;
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
  vscp_fwhlp_hex2bin(key, 32, VSCP_DEFAULT_KEY16);

  // Initialize the CRC
  crcInit();

  print_network_information(g_net_info); // Read back the configuration information and print it

  while (true) {
    // Multicast receive test
    mcast_recv(SOCKET_ID, ethernet_buf, multicast_ip, multicast_port);
  }
}

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