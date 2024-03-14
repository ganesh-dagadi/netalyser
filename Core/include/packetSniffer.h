#include "pcap/pcap.h"
#include <string>
class PacketSniffer
{
private:
    char error[256];
    pcap_t* handler;
    int dLinkHeaderLen;
    std::string filter;
    std::string device;

    void createHandler();
    void getDataLinkHeaderLength();
    void packetHandler();

public:
    // constructors
    PacketSniffer(std::string device, std::string filterString);
    PacketSniffer(std::string filterString);
    PacketSniffer();
    ~PacketSniffer();
    
    //methods
    void beginSniff();
    void stopSniff();
};
