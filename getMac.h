#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <string.h>

uint8_t world_my_mac[ETH_ALEN];

int GetMacAddress()
{
    int nSD; // Socket descriptor
    struct ifreq *ifr; // Interface request
    struct ifconf ifc;
    int i, j ,numif;

     memset(&ifc, 0, sizeof(ifc));
     ifc.ifc_ifcu.ifcu_req = NULL;
     ifc.ifc_len = 0;

     // Create a socket that we can use for all of our ioctls
     nSD = socket( PF_INET, SOCK_DGRAM, 0 );
     if ( nSD < 0 )  return 0;
     if(ioctl(nSD, SIOCGIFCONF, &ifc) < 0) return 0;
     if ((ifr = (ifreq*)  malloc(ifc.ifc_len)) == NULL){
         return 0;
     }
     else{
         ifc.ifc_ifcu.ifcu_req = ifr;
         if (ioctl(nSD, SIOCGIFCONF, &ifc) < 0){
             return 0;
         }
      numif = ifc.ifc_len / sizeof(struct ifreq);
      for (i = 0; i < numif; i++){
          struct ifreq *r = &ifr[i];
          struct sockaddr_in *sin = (struct sockaddr_in *)&r->ifr_addr;
          if (!strcmp(r->ifr_name, "lo")) continue; // skip loopback interface

          if(ioctl(nSD, SIOCGIFHWADDR, r) < 0) return 0;

          for(j = 0; j < ETH_ALEN; j++) world_my_mac[j] = (uint8_t)r->ifr_hwaddr.sa_data[j];

          char macaddr[100];
          sprintf(macaddr, "[%s] %02X:%02X:%02X:%02X:%02X:%02X", r->ifr_name,
           (u_char)r->ifr_hwaddr.sa_data[0],
           (u_char)r->ifr_hwaddr.sa_data[1],
           (u_char)r->ifr_hwaddr.sa_data[2],
           (u_char)r->ifr_hwaddr.sa_data[3],
           (u_char)r->ifr_hwaddr.sa_data[4],
           (u_char)r->ifr_hwaddr.sa_data[5]);
       printf("Your network interface information: %s \n",macaddr);
       //printf("%02X \n",(u_char)r->ifr_hwaddr.sa_data[0]); 0~5 mac address
          return 0;
      }
     }
     close(nSD);
     free(ifr);

     return( 1 );
    }
