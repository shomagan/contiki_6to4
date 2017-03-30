/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *         Slip fallback interface
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 *         Joel Hoglund <joel@sics.se>
 *         Nicolas Tsiftes <nvt@sics.se>
 */

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/slip.h"
#include "dev/uart1.h"
#include "dev/radio.h"
#include <string.h>
#include "dev/rfcore.h"

#define UIP_IP_BUF        ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define DEBUG DEBUG_NONE
//#define PRINTF printf
#include "net/ip/uip-debug.h"
typedef struct output_config {
  radio_value_t power;
  uint8_t txpower_val;
} output_config_t;

static const output_config_t output_power_cc2592[] = {
  { 22, 0xFF },
  {  21.5, 0xED },
  {  20.9, 0xD5 },
  {  20.1, 0xC5 },
  {  19.6, 0xB6 },
  { 19, 0xB0 },
  { 17.8, 0xA1 },
  { 16.4, 0x91 },
  { 14.9, 0x88 },
  { 13, 0x72 },
  { 11, 0x62 },
  { 9.5, 0x58 },
  { 7.5, 0x42 },
};
#define OUTPUT_CONFIG_COUNT_CC2592 (sizeof(output_power_cc2592) / sizeof(output_config_t))

/* Max and Min Output Power in dBm */
#define OUTPUT_POWER_MIN_CC2592    (output_power_cc2592[OUTPUT_CONFIG_COUNT_CC2592 - 1].power)
#define OUTPUT_POWER_MAX_CC2592    (output_power_cc2592[0].power)

/*---------------------------------------------------------------------------*/
/* Returns the current TX power in dBm */
radio_value_t
get_tx_power_cc2592(void)
{
  int i;
  uint8_t reg_val = REG(RFCORE_XREG_TXPOWER) & 0xFF;

  /*
   * Find the TXPOWER value in the lookup table
   * If the value has been written with set_tx_power, we should be able to
   * find the exact value. However, in case the register has been written in
   * a different fashion, we return the immediately lower value of the lookup
   */
  for(i = 0; i < OUTPUT_CONFIG_COUNT_CC2592; i++) {
    if(reg_val >= output_power_cc2592[i].txpower_val) {
      return output_power_cc2592[i].power;
    }
  }
  return OUTPUT_POWER_MIN_CC2592;
}

/*---------------------------------------------------------------------------*/
/*
 * Set TX power to 'at least' power dBm
 * This works with a lookup table. If the value of 'power' does not exist in
 * the lookup table, TXPOWER will be set to the immediately higher available
 * value
 */
static void
set_tx_power_cc2592(radio_value_t power)
{
  int i;
  uint8_t reg_val = REG(RFCORE_XREG_TXPOWER) & 0xFF;

  for(i = OUTPUT_CONFIG_COUNT_CC2592 - 1; i >= 0; --i) {
    if(power <= output_power_cc2592[i].power) {
      if (reg_val!=output_power_cc2592[i].txpower_val){
        REG(RFCORE_XREG_TXPOWER) = output_power_cc2592[i].txpower_val;}
      return;
    }
  }
}


void set_prefix_64(uip_ipaddr_t *);
uip_ipaddr_t inside_prefix;
static uip_ipaddr_t last_sender;
/*---------------------------------------------------------------------------*/
static uint16_t
chksum(uint16_t sum, const uint8_t *data, uint16_t len)
{
  uint16_t t;
  const uint8_t *dataptr;
  const uint8_t *last_byte;

  dataptr = data;
  last_byte = data + len - 1;

  while(dataptr < last_byte) {	/* At least two more bytes */
    t = (dataptr[0] << 8) + dataptr[1];
    sum += t;
    if(sum < t) {
      sum++;		/* carry */
    }
    dataptr += 2;
  }

  if(dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if(sum < t) {
      sum++;		/* carry */
    }
  }

  /* Return sum in host byte order. */
  return sum;
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;
  PRINTF("UIP_DS6_ADDR_NB %u",UIP_DS6_ADDR_NB);  
  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}

/*---------------------------------------------------------------------------*/
static void
slip_input_callback(void)
{
//  svalka
//        device_type_seting

//
  unsigned char i,j;
  unsigned short chek_summ,chek_summ_recv;
  uip_ds6_addr_t *ds6_addr_t;

  chek_summ =0;
 // PRINTF("SIN: %u\n", uip_len);

  if((uip_buf[0] == '!')&&(uip_buf[1] == 'P')) {
    PRINTF("Got configuration message of type %c\n", uip_buf[1]);
    chek_summ =chksum(chek_summ,(uint8_t*)uip_buf,10);
    chek_summ_recv = uip_buf[10];
    chek_summ_recv |= ((uint16_t)uip_buf[11])<<8;
    if (chek_summ_recv==chek_summ){
      if (device_type_seting == TARGET_TYPE){
        device_type_seting=0;
        watchdog_reboot();
      }else{
        leds_on(LEDS_RED);
        time_blink =2;
        device_type_seting=ROUTER_TYPE;
        /* Here we set a prefix !!! */
        memset(&inside_prefix, 0, 16);
        memcpy(&inside_prefix, &uip_buf[2], 8);
        PRINTF("Setting prefix ");
        PRINT6ADDR(&inside_prefix);
        PRINTF("\n");
        set_prefix_64(&inside_prefix);
      }
    }
    uip_clear_buf();
  } else if ((uip_buf[0] == '?') && (uip_buf[1] == 'M')) {
    PRINTF("Got request message of type %c\n", uip_buf[1]);

    char* hexchar = "0123456789abcdef";
    int j;
    /* this is just a test so far... just to see if it works */
    uip_buf[0] = '!';
    for(j = 0; j < 8; j++) {
      uip_buf[2 + j * 2] = hexchar[uip_lladdr.addr[j] >> 4];
      uip_buf[3 + j * 2] = hexchar[uip_lladdr.addr[j] & 15];
    }
    uip_len = 18;
    slip_send();

    uip_clear_buf();
  }else if(strncmp(uip_buf, "AdressRouter", 12) == 0) {
    if (device_type_seting == TARGET_TYPE){
      device_type_seting=0;
      watchdog_reboot();
    }else{
      memcpy(&uip_buf[12],&inside_prefix, 8);
      for (i=8;i<16;i++){
        uip_buf[12+i] = uip_ds6_if.addr_list[2].ipaddr.u8[i];
      }
      PRINTF("uip_ds6_if.addr_list[0].ipaddr.u8 %u,%u,%u \n",
              uip_ds6_if.addr_list[2].ipaddr.u8[0],
              uip_ds6_if.addr_list[2].ipaddr.u8[1],
              uip_ds6_if.addr_list[2].ipaddr.u8[2]);
      //uip_ds6_if.addr_list[0].ipaddr.u8[12+i])
      slip_write(uip_buf, 12+i);
    }
  }else if (strncmp(uip_buf, "AdressTarget", 12) == 0){
    chek_summ =chksum(chek_summ,(uint8_t*)uip_buf,28);
    chek_summ_recv = uip_buf[28];
    chek_summ_recv |= ((uint16_t)uip_buf[29])<<8;
    if (chek_summ_recv==chek_summ){
      if (device_type_seting == ROUTER_TYPE){
        device_type_seting=0;
        watchdog_reboot();
      }else{
        leds_on(LEDS_RED);
        //set new IPv6 addres
        uip_ipaddr_t ipaddr;
        uip_lladdr_t lladdr;

        memset(&inside_prefix, 0, 16);
        memcpy(&inside_prefix, &uip_buf[12], 8);
        lladdr.addr[0] = uip_buf[20];
    		lladdr.addr[1] = uip_buf[21];
    		lladdr.addr[2] = uip_buf[22];
    		lladdr.addr[3] = uip_buf[23];
        lladdr.addr[4] = uip_buf[24];
        lladdr.addr[5] = uip_buf[25];
        lladdr.addr[6] = uip_buf[26];
        lladdr.addr[7] = uip_buf[27];
        if (device_type_seting==0){
/*          uip_ip6addr(&ipaddr, 0x2001, 0x0db8, 0, 0x0212, 0, 0, 0, 0);
          uip_ds6_set_addr_iid(&ipaddr, &lladdr);
          uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);  */

          uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
          uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
          uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
        }
        for(j = 0; j < UIP_DS6_ADDR_NB; j++) {
          for (i=0;i<4;i++){
            if (uip_buf[24+i]!= uip_ds6_if.addr_list[j].ipaddr.u8[12+i])
              break;
          }
          if (i==4)
            break;
          
        }
        if (j==UIP_DS6_ADDR_NB){
          if (device_type_seting==TARGET_TYPE){
            watchdog_reboot();
          }else{
            uip_ds6_addr_rm(&uip_ds6_if.addr_list[0]);
          }
          uip_ds6_set_addr_iid(&inside_prefix, &lladdr);
          ds6_addr_t = uip_ds6_addr_add(&inside_prefix, 0, ADDR_AUTOCONF);
          uip_buf[12] = ds6_addr_t->ipaddr.u8[12];
          uip_buf[13] = ds6_addr_t->ipaddr.u8[13];
          uip_buf[14] = ds6_addr_t->ipaddr.u8[14];
          uip_buf[15] = ds6_addr_t->ipaddr.u8[15];
          slip_write(uip_buf, 16);
        }else{
          uip_buf[12] = lladdr.addr[4];
          uip_buf[13] = lladdr.addr[5];
          uip_buf[14] = lladdr.addr[6];
          uip_buf[15] = lladdr.addr[7];
          slip_write(uip_buf, 16);
        }
        print_local_addresses();
        device_type_seting = TARGET_TYPE;
        time_blink =1;
      }
    }
  }else if((uip_buf[0] == '!')&&(uip_buf[1] == 'T')){
    radio_value_t power;  //power in dbm with cc2592 chip
    chek_summ =chksum(chek_summ,(uint8_t*)uip_buf,3);
    chek_summ_recv = uip_buf[3];
    chek_summ_recv |= ((uint16_t)uip_buf[4])<<8;
    if (chek_summ_recv==chek_summ){
      PRINTF("set transmission power %c\n", uip_buf[2]);
      power = uip_buf[2];
      set_tx_power_cc2592(power);
      power = get_tx_power_cc2592();
      uip_buf[3] = chek_summ_recv;
      uip_buf[4] = chek_summ_recv>>8;
      uip_len = 5;
      slip_send();
      uip_clear_buf();
    }
  }else if((uip_buf[0] == '!')&&(uip_buf[1] == 'C')){
    chek_summ =chksum(chek_summ,(uint8_t*)uip_buf,3);
    chek_summ_recv = uip_buf[3];
    chek_summ_recv |= ((uint16_t)uip_buf[4])<<8;
    if (chek_summ_recv==chek_summ){
      PRINTF("set channel %c\n", uip_buf[2]);
      set_channel(uip_buf[2]) ;// range [11,26]
      uip_buf[2] = get_channel();
      uip_buf[3] = chek_summ_recv;
      uip_buf[4] = chek_summ_recv>>8;
      uip_len = 5;
      slip_send();
      uip_clear_buf();
    }

  } else if ((uip_buf[0] == '?') && (uip_buf[1] == 'R') && (uip_buf[2] == 'P')) {
  //  PRINTF("Got request message of param %c %c\n", uip_buf[1], uip_buf[2]);
    signed short def_rt_rssi;
    unsigned short def_rt_rssi_abs;
    int j;
    /* this is just a test so far... just to see if it works */
    uip_buf[0] = '!';
    uip_buf[1] = 'R';
    uip_buf[2] = 'P';

    def_rt_rssi = (signed short)sicslowpan_get_last_rssi();
    def_rt_rssi_abs = abs(def_rt_rssi);

    uip_buf[3] = (uint8_t)def_rt_rssi_abs;
    uip_buf[4] = (uint8_t)(def_rt_rssi_abs>>8);
    chek_summ =chksum(0,(uint8_t*)uip_buf,5);

    uip_buf[5] = chek_summ;
    uip_buf[6] = chek_summ>>8;

    uip_len = 7;
    slip_send();

    uip_clear_buf();
  }else{
  /* Save the last sender received over SLIP to avoid bouncing the
     packet back if no route is found */
    leds_toggle(LEDS_YELLOW);
//    uip_ipaddr_copy(&last_sender, &UIP_IP_BUF->srcipaddr);
  }
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  slip_arch_init(115200*4);
  process_start(&slip_process, NULL);
  slip_set_input_callback(slip_input_callback);
}
/*---------------------------------------------------------------------------*/
static int
output(void)
{
  if(uip_ipaddr_cmp(&last_sender, &UIP_IP_BUF->srcipaddr)) {
    /* Do not bounce packets back over SLIP if the packet was received
       over SLIP */
/*    PRINTF("slip-bridge: Destination off-link but no route src=");
    PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
    PRINTF(" dst=");
    PRINT6ADDR(&UIP_IP_BUF->destipaddr);
    PRINTF("\n");*/
    slip_send();
  } else {
//    PRINTF("SUT: %u\n", uip_len);
    slip_send();
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
#if !SLIP_BRIDGE_CONF_NO_PUTCHAR
#undef putchar
int
putchar(int c)
{
#define SLIP_END     0300
  static char debug_frame = 0;

  if(!debug_frame) {            /* Start of debug output */
    slip_arch_writeb(SLIP_END);
    slip_arch_writeb('\r');     /* Type debug line == '\r' */
    debug_frame = 1;
  }

  /* Need to also print '\n' because for example COOJA will not show
     any output before line end */
  slip_arch_writeb((char)c);

  /*
   * Line buffered output, a newline marks the end of debug output and
   * implicitly flushes debug output.
   */
  if(c == '\n') {
    slip_arch_writeb(SLIP_END);
    debug_frame = 0;
  }
  return c;
}
#endif
/*---------------------------------------------------------------------------*/
const struct uip_fallback_interface rpl_interface = {
  init, output
};
/*---------------------------------------------------------------------------*/
