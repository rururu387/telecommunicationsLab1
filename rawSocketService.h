#ifndef RAWSOCKETSERVICE_H
#define RAWSOCKETSERVICE_H

/*
    Raw TCP packets
*/
#include <stdio.h>	//for printf
#include <string.h> //memset
#include <sys/socket.h>	//for socket of course
#include <stdlib.h> //for exit(0);
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <arpa/inet.h> // inet_addr
#include <unistd.h> // sleep()
#include <string>
#include <memory>
#include "commonUtils.h"

class RawSocketService
{
public:
    RawSocketService();

    /*
        Generic checksum calculation function
    */
    unsigned short getHashSum(unsigned short *ptr,int nbytes);

    void sendPacket(int socket, std::string to, std::vector<std::byte> datagram);

    std::vector<std::byte> getTCPPayload(std::string from, std::string to, std::wstring dataStr);

    void sendTCPPacket(std::string from, std::string to, std::wstring dataStr);

    std::vector<std::byte> getIPHeader(unsigned char protocol, size_t headerSize, std::string from, std::string to, std::wstring dataStr);

    std::vector<std::byte> getUDPPayload(std::string from, std::string to, std::wstring dataStr);

    void sendUDPPacket(std::string from, std::string to, std::wstring dataStr);
};

/*
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
*/
struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

#endif // RAWSOCKETSERVICE_H
