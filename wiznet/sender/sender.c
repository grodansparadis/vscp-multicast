/**
 * Copyright (c) 2021 WIZnet Co.,Ltd
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * ----------------------------------------------------------------------------------------------------
 * Includes
 * ----------------------------------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "port_common.h"

#include "wizchip_conf.h"
#include "wizchip_spi.h"

#include "loopback.h"

#include <vscp.h>
#include <vscp-firmware-helper.h>
#include <crc.h>

#define MULTICAST_GROUP "224.0.23.158" // Multicast group address (VSCP)
#define MULTICAST_PORT  "9598"         // Multicast port


/**
 * ----------------------------------------------------------------------------------------------------
 * Macros
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
#define PLL_SYS_KHZ (133 * 1000)

/* Buffer */
#define ETHERNET_BUF_MAX_SIZE (1024 * 2)

/* Socket */
#define SOCKET_LOOPBACK 0

/* Port */
#define PORT_LOOPBACK 5000

/**
 * ----------------------------------------------------------------------------------------------------
 * Variables
 * ----------------------------------------------------------------------------------------------------
 */
/* Network */
static wiz_NetInfo g_net_info = {
  .mac = { 0x00, 0x08, 0xDC, 0x12, 0x34, 0x56 }, // MAC address
  .ip  = { 192, 168, 1, 201 },                   // IP address
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

/* Loopback */
static uint8_t g_loopback_buf[ETHERNET_BUF_MAX_SIZE] = {
  0,
};

static uint8_t dest_ip[4] = { 224, 0, 23, 158 };

/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
static void
set_clock_khz(void);

/**
 * ----------------------------------------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------------------------------------
 */
int
main()
{
  /* Initialize */
  int retval = 0;

  set_clock_khz();

  stdio_init_all();

  wizchip_spi_initialize();
  wizchip_cris_initialize();

  wizchip_reset();
  wizchip_initialize();
  wizchip_check();

  network_initialize(g_net_info);

  /* Get network information */
  print_network_information(g_net_info);

  /* Infinite loop */
  while (1) {
    /* UDP Client loopback test */
    if ((retval = loopback_udpc(SOCKET_LOOPBACK, g_loopback_buf, dest_ip, PORT_LOOPBACK)) < 0) {
      printf(" Loopback error : %d\n", retval);

      while (1)
        ;
    }
  }
}

/**
 * ----------------------------------------------------------------------------------------------------
 * Functions
 * ----------------------------------------------------------------------------------------------------
 */
/* Clock */
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
