#pragma once
// 출처: https://technote.kr/176 [TechNote.kr]
#include "getMac.h"
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

char *world_argv;
uint8_t world_split_my_ip[4];
uint8_t world_split_target_ip[4];
uint8_t world_split_sender_ip[4];

void line_print(){
    for(int i = 0; i < 5; i++) printf("------------");
    printf("\n");
}

void GetIpAddress(){

    struct ifreq ifr;
    char ipstr[40];
    int s;
    int j = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, world_argv, IFNAMSIZ);

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("Error");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
        printf("Your network Address information : %s\n", ipstr);

    /**************** Split ip address ***************************/
        world_split_my_ip[j++] = (uint8_t)atoi(strtok(ipstr, ".")); // 0-192/*
        for(j; j < 4; j++){ world_split_my_ip[j] = (uint8_t)atoi(strtok(NULL, ".")); }
    }
    /*printf("TEST my ip Split"
           "d : %d, %d, %d, %d\n", world_split_my_ip[0], world_split_my_ip[1], world_split_my_ip[2], world_split_my_ip[3]);*/
}

void sender_ip_split(char *c){

    int j = 0;
    world_split_sender_ip[j++] = (uint8_t)atoi(strtok(c, ".")); // 0-192/*
    for( j ; j < 4; j++){ world_split_sender_ip[j] = (uint8_t)atoi(strtok(NULL, ".")); }
}

void target_ip_split(char *c){

    int j = 0;
    world_split_target_ip[j++] = (uint8_t)atoi(strtok(c, ".")); // 0-192/*
    for( j ; j < 4; j++){ world_split_target_ip[j] = (uint8_t)atoi(strtok(NULL, ".")); }
}

