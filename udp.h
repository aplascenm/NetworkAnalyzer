#ifndef UDP_H_INCLUDED
#define UDP_H_INCLUDED
#include <iostream>
#include "diccionario.h"
#include "dns.h"
#include "dhcp.h"
using namespace std;


void udp(const struct pcap_pkthdr *header, const u_char *buffer, int type)
{
    unsigned char currentByte;
    stringstream packetStream;
    string packetData;

    for(unsigned int j=0; j<header->len; j++)
    {
            packetStream<<buffer[j];
    }

    packetData=packetStream.str();

    if(type==4)
    {
        cout<<endl<<endl<<"                UDP - IPV4                 "<<endl;
        /*//Source IP
        cout<<endl<<"Source IP: ";
        for(int j=34; j<38; j++)
        {
            cb=s[j];
            printf("%d", (unsigned int)cb);
            if(j<37)
            {
                cout<<".";
            }
        }
        //Destination
        cout<<endl<<"Destination IP: ";
        for(int j=38; j<42; j++)
        {
            cb=s[j];
            printf("%d", (unsigned int)cb);
            if(j<41)
            {
                cout<<".";
            }
        }*/
        char *bin;

        //Source Port
        long int udpLength,sourcePort,destinationPort;
        stringstream binaryStream;
        string binaryData;
        char *endPointer;

        currentByte=packetData[34];
        bin=chartobin(currentByte);
        binaryStream<<bin;

        currentByte=packetData[35];
        bin=chartobin(currentByte);
        binaryStream<<bin;

        binaryData=binaryStream.str();
        sourcePort=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Source Port: "<<sourcePort;
        
        //Destination Port
        stringstream destinationStream;

        currentByte=packetData[36];
        bin=chartobin(currentByte);
        destinationStream<<bin;

        currentByte=packetData[37];
        bin=chartobin(currentByte);
        destinationStream<<bin;

        binaryData=destinationStream.str();
        destinationPort=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Destination Port: "<<destinationPort;
        
        //Lenght
        stringstream lengthStream;

        currentByte=packetData[38];
        bin=chartobin(currentByte);
        lengthStream<<bin;

        currentByte=packetData[39];
        bin=chartobin(currentByte);
        lengthStream<<bin;

        binaryData=lengthStream.str();
        udpLength=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Lenght: "<<udpLength;
        
        //Checksum
        stringstream checksumStream;

        currentByte=packetData[40];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        currentByte=packetData[41];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        binaryData="0x"+checksumStream.str();
        
        cout<<endl<<"Header Checksum: "<<binaryData;
        
        //IFDNS
        if(sourcePort==53)
        {
            dns(header, buffer, 4, 1);
        }
        else if (destinationPort==53)
        {
            dns(header, buffer, 4, 2);
        }

        if(sourcePort==67)
        {
            dhcp(header, buffer, 1);
        }
        else if(destinationPort==67)
        {
            dhcp(header, buffer, 2);
        }

    }
    else
    {
        cout<<endl<<endl<<"                UDP - IPV6                 "<<endl;
        
        char *bin;
        
        //Source Port
        long int udpLength,sourcePort,destinationPort;
        stringstream binaryStream;
        string binaryData;
        char *endPointer;

        currentByte=packetData[54];
        bin=chartobin(currentByte);
        binaryStream<<bin;

        currentByte=packetData[55];
        bin=chartobin(currentByte);
        binaryStream<<bin;

        binaryData=binaryStream.str();
        sourcePort=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Source Port: "<<sourcePort;
        
        //Destination Port
        stringstream destinationStream;

        currentByte=packetData[56];
        bin=chartobin(currentByte);
        destinationStream<<bin;

        currentByte=packetData[57];
        bin=chartobin(currentByte);
        destinationStream<<bin;

        binaryData=destinationStream.str();
        destinationPort=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Destination Port: "<<destinationPort;
        
        //Lenght
        stringstream lengthStream;

        currentByte=packetData[58];
        bin=chartobin(currentByte);
        lengthStream<<bin;

        currentByte=packetData[59];
        bin=chartobin(currentByte);
        lengthStream<<bin;

        binaryData=lengthStream.str();
        udpLength=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Lenght: "<<udpLength;
        
        //Checksum
        stringstream checksumStream;

        currentByte=packetData[60];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        currentByte=packetData[61];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        binaryData="0x"+checksumStream.str();
        
        cout<<endl<<"Header Checksum: "<<binaryData;
        
        //IFDNS
        if(sourcePort==53)
        {
            dns(header, buffer, 6, 1);
        }
        else if (destinationPort==53)
        {
            dns(header, buffer, 6, 2);
        }

        if(sourcePort==67)
        {
            dhcp(header, buffer, 1);
        }
        else if(destinationPort==67)
        {
            dhcp(header, buffer, 2);
        }
    }
}

#endif // UDP_H_INCLUDED
