#include <stdio.h>
#include "port_common.h"

#include "wizchip_conf.h"
#include "wizchip_spi.h"
#include "socket.h"
#include "loopback.h"
#include "multicast.h" // Use multicast

/* Clock */
#define PLL_SYS_KHZ (133 * 1000)

/* Buffer */
#define SOCKET_ID             0          // Socket number
#define ETHERNET_BUF_MAX_SIZE (1024 * 2) // Send and receive cache size

static wiz_NetInfo g_net_info = {
  .mac = { 0x00, 0x08, 0xDC, 0x12, 0x34, 0x56 }, // MAC address
  .ip  = { 192, 168, 1, 180 },                   // IP address
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

static uint8_t ethernet_buf[ETHERNET_BUF_MAX_SIZE] = {
  0,
};
static uint8_t multicast_ip[4] = { 224, 0, 23, 158 }; // VSCP multicast ip address
static uint16_t multicast_port = 9598;                // VSCP multicast port

static void
set_clock_khz(void);

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

  print_network_information(g_net_info); // Read back the configuration information and print it

  while (true) {
    // Multicast receive test
    //multicast_recv(SOCKET_ID, ethernet_buf, multicast_ip, multicast_port);
    printf("Multicast receive test\n");
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