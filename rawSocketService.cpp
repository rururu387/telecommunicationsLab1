#include "rawSocketService.h"

RawSocketService::RawSocketService()
{}
/*
    Generic checksum calculation function
*/
unsigned short RawSocketService::getHashSum(unsigned short *ptr,int nbytes)
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


void RawSocketService::sendPacket(int socket, std::string to, std::vector<std::byte> datagram)
{
    struct iphdr *iph = (struct iphdr*) (datagram.data());
    if(socket == -1)
    {
        //socket creation failed, may be because of non-root privileges
        CommonUtils::showMessage("Failed to create socket. Make sure you are running as SU");
        close(socket);
        return;
    }

    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(to.c_str());

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;

    if (setsockopt(socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        CommonUtils::showMessage("Error setting IP_HDRINCL");
        close(socket);
        return;
    }

    //Send the packet
    if (sendto(socket, (void*)datagram.data(), iph->tot_len , 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
        CommonUtils::showMessage("sendto failed");
        close(socket);
        return;
    }
    //Data send successfully
    else
    {
        std::string message = "Packet Send. Length: ";
        message.append(std::to_string(iph->tot_len));
        message.append("\n");
        CommonUtils::showMessage(message);
    }
    close(socket);
}


std::vector<std::byte> RawSocketService::getIPHeader(unsigned char protocol, size_t headerSize, std::string from, std::string to, std::wstring data)
{
    //Datagram to represent the packet
    std::vector<std::byte> datagram(4096, std::byte{0});

    //IP header
    struct iphdr *iph = (struct iphdr *) (datagram.data());

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + headerSize + (data.size() * sizeof(wchar_t) / sizeof(char));
    iph->id = htonl (54321);	//Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = protocol;
    iph->check = 0;		//Set to 0 before calculating checksum
    iph->saddr = inet_addr (from.c_str());	//Spoof the source ip address
    iph->daddr = inet_addr(to.c_str());

    //Ip checksum
    iph->check = getHashSum((unsigned short *) (datagram.data()), iph->tot_len);

    return datagram;
}

std::vector<std::byte> RawSocketService::getTCPPayload(std::string from, std::string to, std::wstring dataStr)
{
    auto datagram = getIPHeader(IPPROTO_TCP,  sizeof(struct tcphdr), from, to, dataStr);

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) ((datagram.data()) + sizeof (struct ip));

    struct pseudo_header psh;

    //Data part
    char *pseudogram;
    wchar_t* data = (wchar_t*)(datagram.data()) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    wcscpy(data, dataStr.c_str());

    //TCP Header
    tcph->source = htons(1234);
    tcph->dest = htons(80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;	//tcp header size
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(5840);	/* maximum allowed window size */
    tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    //Now the TCP checksum
    psh.source_address = inet_addr(from.c_str());
    psh.dest_address = inet_addr(to.c_str());
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    size_t dataSize = wcslen(data) * sizeof(wchar_t) / sizeof(char);
    psh.tcp_length = htons(sizeof(struct tcphdr) + dataSize);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + dataSize;
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + dataSize);

    tcph->check = getHashSum( (unsigned short*) pseudogram , psize);
    free(pseudogram);

    return datagram;
}

void RawSocketService::sendTCPPacket(std::string from, std::string to, std::wstring dataStr)
{
    std::vector<std::byte> datagram = getTCPPayload(from, to, dataStr);

    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

    sendPacket(s, to, datagram);
}





std::vector<std::byte> RawSocketService::getUDPPayload(std::string from, std::string to, std::wstring dataStr)
{
    auto datagram = getIPHeader(IPPROTO_UDP,  sizeof(struct udphdr), from, to, dataStr);

    //TCP header
    struct udphdr *udph = (struct udphdr *) ((datagram.data()) + sizeof (struct ip));

    struct pseudo_header psh;

    //Data part
    char *pseudogram;
    wchar_t* data = (wchar_t*)(datagram.data()) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    wcscpy(data, dataStr.c_str());

    size_t dataSize = wcslen(data) * sizeof(wchar_t) / sizeof(char);

    //UDP Header
    udph->source = htons(1234);
    udph->dest = htons(80);
    udph->len = sizeof(struct udphdr) + dataSize;
    udph->check = 0;	//leave checksum 0 now, filled later by pseudo header

    //Now the UDP checksum
    psh.source_address = inet_addr(from.c_str());
    psh.dest_address = inet_addr(to.c_str());
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.tcp_length = htons(sizeof(struct udphdr) + dataSize);

    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + dataSize;
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + dataSize);

    udph->check = getHashSum( (unsigned short*) pseudogram , psize);
    free(pseudogram);

    return datagram;
}

void RawSocketService::sendUDPPacket(std::string from, std::string to, std::wstring dataStr)
{
    std::vector<std::byte> datagram = getUDPPayload(from, to, dataStr);

    //Create a raw socket
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);

    sendPacket(s, to, datagram);
}
