#ifndef IPV6_H_INCLUDED
#define IPV6_H_INCLUDED
#include <iostream>
#include <pcap.h>
#include <string>
#include "diccionario.h"
#include "icmpv6.h"
#include "udp.h"
#include "tcp.h"
using namespace std;


void diripv6(char *c)
{

}

void versionipv6(char *bitString)
{
    string binaryPart;
    stringstream versionStream;
    int versionValue;
    char *endPointer;

    for(int i=0; i<4; i++)
    {
        versionStream<<bitString[i];
    }

    binaryPart=versionStream.str();
    versionValue=strtoull(binaryPart.c_str(), &endPointer, 2);
    
    cout<<"Version: "<<versionValue<<" ("<<binaryPart<<")"<<" -> IPV6";
}

void trafficClass(char *firstByteBits, char *secondByteBits)
{
    string firstPartBinary,secondPartBinary;
    stringstream firstStream, secondStream;
    int n, n2;
    char *endPointer;

    for(int i=4; i<8; i++)
    {
        firstStream<<firstByteBits[i];
    }

    firstPartBinary=firstStream.str();
    n=strtoull(firstPartBinary.c_str(), &endPointer, 2);

    for(int i=0; i<4; i++)
    {
        secondStream<<secondByteBits[i];
    }

    secondPartBinary=secondStream.str();
    n2=strtoull(firstPartBinary.c_str(), &endPointer, 2);

    printf("\nTraffic Class: 0x%02x%02x",n, n2);
}

void flowLabel(char *firstByteBits, char *secondByteBits, char *thirdByteBits)
{
    string binarySegment,completeBinary;
    stringstream firstStream, secondStream, thirdStream, combinedStream;
    unsigned long int flowLabelValue;
    char *endPointer;

    for(int i=4; i<8; i++)
    {
        firstStream<<firstByteBits[i];
    }

    binarySegment=firstStream.str();
    ///n=strtoull(s.c_str(), &cc, 2);
    combinedStream<<binarySegment;

    for(int i=0; i<8; i++)
    {
        secondStream<<secondByteBits[i];
    }

    binarySegment=secondStream.str();
    combinedStream<<binarySegment;
    ///n=strtoull(s.c_str(), &cc, 2);

    for(int i=0; i<8; i++)
    {
        thirdStream<<thirdByteBits[i];
    }

    binarySegment=thirdStream.str();
    combinedStream<<binarySegment;

    completeBinary=combinedStream.str();
    flowLabelValue=strtoull(completeBinary.c_str(), &endPointer, 2);
    
    cout<<endl<<"Flow Label: "<<flowLabelValue;
}

void ipv6(const struct pcap_pkthdr *header, const u_char *buffer)
{
    //int tam;
    unsigned char currentByte;
    stringstream packetStream;
    string packetData;

    for(unsigned int j=0; j<header->len; j++)
    {
        packetStream<<buffer[j];
    }

    packetData=packetStream.str();

    cout<<endl<<"                IPV6                 "<<endl;
    
    char *bin, *bin2, *bin3;
    
    ///-------------version---------------------
    currentByte=packetData[14];
    bin=chartobin(currentByte);
    versionipv6(bin);
    
    ///----------Traffic class-------------------
    currentByte=packetData[14];
    bin=chartobin(currentByte);

    currentByte=packetData[15];
    bin2=chartobin(currentByte);

    trafficClass(bin, bin2);
    
    ///----------Flow Label-----------------------
    currentByte=packetData[15];
    bin=chartobin(currentByte);

    currentByte=packetData[16];
    bin2=chartobin(currentByte);

    currentByte=packetData[17];
    bin3=chartobin(currentByte);

    flowLabel(bin, bin2, bin3);
    
    ///----------Payload Lenght-------------------
    char *endPointer;
    long int totalLength, dataLength;
    stringstream lengthStream;
    string binaryLength;

    currentByte=packetData[18];
    bin=chartobin(currentByte);
    lengthStream<<bin;

    currentByte=packetData[19];
    bin=chartobin(currentByte);
    lengthStream<<bin;

    binaryLength=lengthStream.str();
    totalLength=strtoull(binaryLength.c_str(), &endPointer, 2);
    
    dataLength=totalLength-40;
    
    cout<<endl<<"Payload Lenght: "<<totalLength;
    
    ///----------Next Header-------------------
    int nextHeaderValue;
    stringstream protocolStream;

    currentByte=packetData[20];
    protocolStream<<(unsigned int)currentByte;

    binaryLength=protocolStream.str();
    nextHeaderValue=verificarIPT6(binaryLength);

    ///----------Hop Limit---------------------
    currentByte=packetData[21];
    cout<<endl<<"Hop Limit: "<<(unsigned int)currentByte;

    ///----------Source address----------------
    cout<<endl<<"Source Address: ";

    int groupCounter=0;

    for(int j=22; j<38; j++)
    {
        currentByte=packetData[j];
        printf("%02x", (unsigned int)currentByte);

        groupCounter++;

        if(j<37)
        {
            if(groupCounter==2)
            {
            groupCounter=0;
            cout<<":";
            }
        }
    }

    /*tam=16;
    ar.seekg (22, ios::beg);
    ar.read ((char*)ch, tam);
    stringstream sa;
    int cont=0;
    for(int j=0; j<16; j++)
    {
        sa<<hex<<setw(2)<<setfill('0')<<(int)ch[j];
        cont++;
        if(j<15)
        {
            if(cont==2)
            {
                cont=0;
                sa<<":";
            }
        }
    }
    s=sa.str();
    cout<<endl<<"Source Address: "<<s;*/
    
    ///----------Destination address-----------
    cout<<endl<<"Destination Address: ";

    groupCounter=0;

    for(int j=38; j<54; j++)
    {
        currentByte=packetData[j];
        printf("%02x", (unsigned int)currentByte);

        groupCounter++;

        if(j<53)
        {
            if(groupCounter==2)
            {
            groupCounter=0;
            cout<<":";
            }
        }
    }

    /*tam=16;
    ar.seekg (38, ios::beg);
    ar.read ((char*)ch, tam);
    stringstream sd;
    cont=0;
    for(int j=0; j<16; j++)
    {
        sd<<hex<<setw(2)<<setfill('0')<<(int)ch[j];
        cont++;
        if(cont==2)
        {
            if(j<15)
            {
                cont=0;
                sd<<":";
            }
        }
    }
    s=sd.str();
    cout<<endl<<"Destination Address: "<<s;*/

    ///-----------------DATA--------------------
    if(nextHeaderValue==58)
    {
        icmp6(header, buffer, dataLength);
    }
    else if(nextHeaderValue==17)
    {
        udp(header,buffer,6);
    }
    else if(nextHeaderValue==6)
    {
        tcp(header, buffer, 6);
    }
}

#endif // IPV6_H_INCLUDED
