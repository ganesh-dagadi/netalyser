#include <iostream>
#include "./include/packetSniffer.h"
// using namespace std;

int main(){
    PacketSniffer* sniffer = new PacketSniffer();
    sniffer->beginSniff();
    return 0;
}