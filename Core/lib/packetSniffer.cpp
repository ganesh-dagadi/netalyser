#include <iostream>
#include "../include/packetSniffer.h"
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
//constructor
PacketSniffer::PacketSniffer(){
    this->device = "";
    this->filter = "";
}
PacketSniffer::PacketSniffer(std::string device, std::string filterString){
    this->device = device;
    this->filter = filterString;
}

PacketSniffer::PacketSniffer(std::string filterString){
    this->device = "";
    this->filter = filterString;
}

//public methods
void PacketSniffer::beginSniff(){
    this->createHandler();
}

void PacketSniffer::stopSniff(){

}

//private methods
void PacketSniffer::createHandler(){
    pcap_if_t* devices;
    bpf_u_int32 netIP;
    bpf_u_int32 netMask;
    char device_char[256];
    if(this->device.size() == 0){
        //get the default device
        if(pcap_findalldevs(&devices , this->error)){   
            std::cout << this->error << std::endl;
            throw std::runtime_error("Device lookp failed");
        }
        this->device = devices[0].name;
    }
    std::strcpy(device_char , this->device.c_str());
    if(pcap_lookupnet(device_char , &netIP , &netMask , this->error)){
        std::cout << this->error << std::endl;
        throw std::runtime_error("Device ip and mask lookup failed");
    }

    //send message to spring saying listening on netip and netmask
    struct in_addr addr = {netIP};
    std::cout << "Listening on " << inet_ntoa(addr) << std::endl;

    this->handler = pcap_open_live(device_char , BUFSIZ , 1 , 1000 , this->error);
    if(this->handler == NULL){
        std::cout << this->error << std::endl;
        throw std::runtime_error("Unable to open device for capture");
    }
    // todo filter later

}

void PacketSniffer::getDataLinkHeaderLength(){
    int headerType;
    if((headerType = pcap_datalink(this->handler) == PCAP_ERROR_NOT_ACTIVATED)){
        std::cout << "Error handler not activated" << std::endl;
        throw new std::runtime_error("Error handler not activated");
    }
    switch (headerType)
    {
     case DLT_NULL:
        this->dLinkHeaderLen = 4;
        break;
 
    case DLT_EN10MB:
        this->dLinkHeaderLen = 14;
        break;
 
    case DLT_SLIP:
    case DLT_PPP:
    case DLT_IEEE802_11:
        this->dLinkHeaderLen = 24;
        break;
    default:
       this->dLinkHeaderLen = 0;
       throw new std::runtime_error("Unsupported link layer type");
    }

}