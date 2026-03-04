#ifndef IPV4_H_INCLUDED
#define IPV4_H_INCLUDED
#include <iostream>
#include <string>
#include "diccionario.h"
#include "icmpv4.h"
#include "ethernet.h"
#include "udp.h"
#include "tcp.h"
using namespace std;


int versionIhl(char *bitString)
{
    string binaryPart;
    stringstream versionStream, ihlStream;
    int n;
    char *endPointer;

    for(int i=0; i<4; i++)
    {
        versionStream<<bitString[i];
    }

    binaryPart=versionStream.str();
    n=strtoull(binaryPart.c_str(), &endPointer, 2);

    cout<<"Version: "<<n<<" ("<<binaryPart<<")"<<" -> IPV4";
    
    for(int i=4; i<8; i++)
    {
        ihlStream<<bitString[i];
    }
    
    binaryPart=ihlStream.str();
    n=strtoull(binaryPart.c_str(), &endPointer, 2);

    cout<<endl<<"IHL: "<<n<<" ("<<n*4<<")";

    return n*4;
}

void dscpEcn(char *bitString)
{
    string binaryPart;
    stringstream dscpStream;
    int n;
    char *endPointer;

    for(int i=0; i<6; i++)
    {
        dscpStream<<bitString[i];
    }

    binaryPart=dscpStream.str();
    n=strtoull(binaryPart.c_str(), &endPointer, 2);
    
    cout<<endl<<"DSCP: "<<n;
    
    if(bitString[6]=='1')
    {
        cout<<endl<<"ECN bit 1: ON";
    }
    else
    {
        cout<<endl<<"ECN bit 1: OFF";
    }

    if(bitString[7]=='1')
    {
        cout<<endl<<"ECN bit 2: ON";
    }
    else
    {
        cout<<endl<<"ECN bit 2: OFF";
    }
}

void flags (char *c)
{
    if(c[0]=='1')
    {
        cout<<endl<<"MSB Reservado: ON";
    }else
    {
        cout<<endl<<"MSB Reservado: OFF";
    }
    if(c[1]=='1')
    {
        cout<<endl<<"More Fragments: ON";
    }else
    {
        cout<<endl<<"More Fragments: OFF";
    }
    if(c[2]=='1')
    {
        cout<<endl<<"Dont Fragments: ON";
    }else
    {
        cout<<endl<<"Dont Fragments: OFF";
    }
}

void fragmetsOffset(char *firstByteBits, char *secondByteBits)
{
    string binaryPart;
    stringstream firstStream, secondStream;
    int n, n2;
    char *endPointer;

    for(int i=3; i<8; i++)
    {
        firstStream<<firstByteBits[i];
    }

    binaryPart=firstStream.str();
    n=strtoull(binaryPart.c_str(), &endPointer, 2);

    for(int i=0; i<8; i++)
    {
        secondStream<<secondByteBits[i];
    }

    binaryPart=secondStream.str();
    n2=strtoull(binaryPart.c_str(), &endPointer, 2);

    cout<<endl<<"Fragment Offset: "<<n+n2;
}

void identificar(int n,const struct pcap_pkthdr *header, const u_char *buffer, int t)
{
    if(n==1)
    {
        icmp4(header, buffer,t);
    }else if(n==6)
    {
        tcp(header, buffer, 4);
    }else if(n==17)
    {
        udp(header, buffer, 4);
    }
}

void ipv4(const struct pcap_pkthdr *header, const u_char *buffer)
{
    int headerLength;
    stringstream packetStream;
    string packetData;

    char *bin, *bin2;
    unsigned char currentByte;

    for(unsigned int j=0; j<header->len; j++)
    {
        packetStream<<buffer[j];
    }

    packetData=packetStream.str();

    cout<<endl<<"                IPV4                 "<<endl;
    
    ///-------MSB Y LSB----------------
    currentByte=packetData[14];
    bin=chartobin(currentByte);
    headerLength=versionIhl(bin);
    
    ///-------DSCP Y ECN---------------
    currentByte=packetData[15];
    bin=chartobin(currentByte);
    dscpEcn(bin);
    
    ///-------Total Lenght-------------
    long int totalLength,payloadLength;
    stringstream totalLengthStream;
    string binaryData;
    char *endPointer;

    currentByte=packetData[16];
    bin=chartobin(currentByte);
    totalLengthStream<<bin;

    currentByte=packetData[17];
    bin=chartobin(currentByte);
    totalLengthStream<<bin;

    binaryData=totalLengthStream.str();
    totalLength=strtoull(binaryData.c_str(), &endPointer, 2);
    
    payloadLength=totalLength-20;
    
    cout<<endl<<"Total Lenght: "<<totalLength;
    
    ///------Identification------------
    stringstream identificationStream;

    currentByte=packetData[18];
    bin=chartobin(currentByte);
    identificationStream<<bin;

    currentByte=packetData[19];
    bin=chartobin(currentByte);
    identificationStream<<bin;

    binaryData=identificationStream.str();
    totalLength=strtoull(binaryData.c_str(), &endPointer, 2);
    
    cout<<endl<<"Identification: "<<totalLength;
   
    ///---------FLAGS-------------------
    currentByte=packetData[20];
    bin=chartobin(currentByte);
    flags(bin);
    
    ///---------Fragment Offset---------
    bin=chartobin(currentByte);
    currentByte=packetData[21];
    
    bin2=chartobin(currentByte);
    fragmetsOffset(bin, bin2);

    ///----------Time To Life-----------
    currentByte=packetData[22];
    cout<<endl<<"Time to life: "<<(unsigned int)currentByte;
    
    ///---------Protocol----------------
    int protocolNumber;
    stringstream protocolStream;

    protocolStream<<(int)packetData[23];
    binaryData=protocolStream.str();
    protocolNumber=verificarIPT(binaryData);

    ///--------Header Checksum----------
    stringstream checksumStream;
    string checksumString;

    currentByte=packetData[24];
    checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
    
    currentByte=packetData[25];
    checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
    
    checksumString="0x"+checksumStream.str();
    
    cout<<endl<<"Header Checksum: "<<checksumString;
    
    ///---------Direccion Origen-----------
    cout<<endl<<"Sender IP: ";

    for(int j=26; j<30; j++)
    {
        currentByte=packetData[j];

        printf("%d", (unsigned int)currentByte);

        if(j<29)
        {
            cout<<".";
        }
    }

    ///---------Direccion Destino----------
    cout<<endl<<"Tarjet IP: ";
    
    for(int j=30; j<34; j++)
    {
        currentByte=packetData[j];
        
        printf("%d", (unsigned int)currentByte);
        
        if(j<33)
        {
            cout<<".";
        }
    }
    
    ///-----------Data----------------------
    identificar(protocolNumber, header, buffer,payloadLength);
}

#endif // IPV4_H_INCLUDED
