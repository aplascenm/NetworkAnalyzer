#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED
#include <iostream>
#include "diccionario.h"
#include "http.h"
using namespace std;


void dataresns(char *bitString)
{
    //Data Offset
    string binaryPart;
    stringstream offsetStream, reservedStream;
    int n;
    char *endPointer;

    for(int i=0; i<4; i++)
    {
        offsetStream<<bitString[i];
    }

    binaryPart=offsetStream.str();
    n=strtoull(binaryPart.c_str(), &endPointer, 2);
    
    cout<<endl<<"Data offset: "<<n<<" ->"<<binaryPart<<" ("<<n*4<<")";
    
    //Reserved
    for(int i=5; i<7; i++)
    {
        reservedStream<<bitString[i];
    }
    
    binaryPart=reservedStream.str();
    n=strtoull(binaryPart.c_str(), &endPointer, 2);
    
    cout<<endl<<"Reserved Bits: "<<n;
    
    //Bandera NS
    if(bitString[7]=='1')
    {
        cout<<endl<<"Bandera NS: ON";
    }
    else
    {
        cout<<endl<<"Bandera NS: OFF";
    }
}

void flagst(char *c)
{
    for(int i=0; i<8; i++)
    {
        if(c[i]=='1')
        {
            cout<<endl<<flagstcp[i]<<"ON";
        }else
        {
            cout<<endl<<flagstcp[i]<<"OFF";
        }
    }
}

void tcp (const struct pcap_pkthdr *header, const u_char *buffer, int type)
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
        cout<<endl<<endl<<"                TCP - IPV4                 "<<endl;
        
        char *bin;
        
        //Source Port
        long int sourcePort, destinationPort;
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
        
        //Seq Number
        long long int sequenceNumber;
        stringstream sequenceStream;

        currentByte=packetData[38];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        currentByte=packetData[39];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        currentByte=packetData[40];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        currentByte=packetData[41];
        bin=chartobin(currentByte);
        sequenceStream<<bin;
        
        binaryData=sequenceStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Seq Number: "<<sequenceNumber;
        
        //Ack Number
        stringstream acknowledgmentStream;

        currentByte=packetData[42];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        currentByte=packetData[43];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        currentByte=packetData[44];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        currentByte=packetData[45];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        binaryData=acknowledgmentStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Ack Number: "<<sequenceNumber;
        
        //Data Offset
        currentByte=packetData[46];
        bin=chartobin(currentByte);
        dataresns(bin);
        
        //Flags
        currentByte=packetData[47];
        bin=chartobin(currentByte);
        flagst(bin);
        
        //Windows Size
        stringstream windowStream;

        currentByte=packetData[48];
        bin=chartobin(currentByte);
        windowStream<<bin;

        currentByte=packetData[49];
        bin=chartobin(currentByte);
        windowStream<<bin;

        binaryData=windowStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Windows Size: "<<sequenceNumber;
        
        //Checksum
        stringstream checksumStream;

        currentByte=packetData[50];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        currentByte=packetData[51];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        binaryData="0x"+checksumStream.str();

        cout<<endl<<"Checksum: "<<binaryData;

        //Urgen Pointer
        stringstream urgentStream;

        currentByte=packetData[52];
        bin=chartobin(currentByte);
        urgentStream<<bin;

        currentByte=packetData[53];
        bin=chartobin(currentByte);
        urgentStream<<bin;

        binaryData=urgentStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Urgent Pointer: "<<sequenceNumber;
        
        //
        if(sourcePort==80||destinationPort==80)
        {
            http(header, buffer);
        }
    }
    else
    {
        cout<<endl<<endl<<"                TCP - IPV6                 "<<endl;
        char *bin;
        
        //Source Port
        long int portValue;
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
        portValue=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Source Port: "<<portValue;
        
        //Destination Port
        stringstream destinationStream;

        currentByte=packetData[56];
        bin=chartobin(currentByte);
        destinationStream<<bin;

        currentByte=packetData[57];
        bin=chartobin(currentByte);
        destinationStream<<bin;

        binaryData=destinationStream.str();
        portValue=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Destination Port: "<<portValue;
        
        //Seq Number
        long long int sequenceNumber;
        stringstream sequenceStream;

        currentByte=packetData[58];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        currentByte=packetData[59];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        currentByte=packetData[60];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        currentByte=packetData[61];
        bin=chartobin(currentByte);
        sequenceStream<<bin;

        binaryData=sequenceStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Seq Number: "<<sequenceNumber;
        
        //Ack Number
        stringstream acknowledgmentStream;

        currentByte=packetData[62];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        currentByte=packetData[63];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        currentByte=packetData[64];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        currentByte=packetData[65];
        bin=chartobin(currentByte);
        acknowledgmentStream<<bin;

        binaryData=acknowledgmentStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Ack Number: "<<sequenceNumber;
        
        //Data Offset
        currentByte=packetData[66];
        bin=chartobin(currentByte);
        dataresns(bin);
        
        //Flags
        currentByte=packetData[67];
        bin=chartobin(currentByte);
        flagst(bin);
        
        //Windows Size
        stringstream windowStream;

        currentByte=packetData[68];
        bin=chartobin(currentByte);
        windowStream<<bin;

        currentByte=packetData[69];
        bin=chartobin(currentByte);
        windowStream<<bin;

        binaryData=windowStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Windows Size: "<<sequenceNumber;
        
        //Checksum
        stringstream checksumStream;

        currentByte=packetData[70];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        currentByte=packetData[71];
        checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
        
        binaryData="0x"+checksumStream.str();
        
        cout<<endl<<"Checksum: "<<binaryData;
        
        //Urgen Pointer
        stringstream urgentStream;

        currentByte=packetData[72];
        bin=chartobin(currentByte);
        urgentStream<<bin;

        currentByte=packetData[73];
        bin=chartobin(currentByte);
        urgentStream<<bin;

        binaryData=urgentStream.str();
        sequenceNumber=strtoull(binaryData.c_str(), &endPointer, 2);
        
        cout<<endl<<"Urgent Pointer: "<<sequenceNumber;
    }
}

#endif // TCP_H_INCLUDED
