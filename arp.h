#ifndef ARP_H_INCLUDED
#define ARP_H_INCLUDED
#include <iostream>
#include "diccionario.h"
using namespace std;


void arp (const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned char current_byte;
    stringstream packet_stream;
    string packet_string;
    
    //Convert raw buffer to string
    for(unsigned int j=0; j<header->len; j++)
    {
        packet_stream<<buffer[j];
    }
    
    packet_string=packet_stream.str();
    
    cout<<endl<<"                ARP                 "<<endl;
    
    ///-------Hardware type------------------------
    char *binary_ptr, *end_ptr;
    long int hardware_type_decimal;
    string binary_string;
    stringstream binary_stream,decimal_stream;
    
    current_byte=packet_string[14];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;
    
    current_byte=packet_string[15];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;
    
    binary_string=binary_stream.str();
    hardware_type_decimal=strtoull(binary_string.c_str(), &end_ptr, 2);
    
    decimal_stream<<hardware_type_decimal;
    binary_string=decimal_stream.str();
    
    verificarHT(binary_string);
    //cout<<endl<<"Hardware Type: "<<s;
    /*cout<<endl<<"Hardware Type: "<<(int)ch[0];
    if((int)ch[0]==1)
    {
        cout<<" -> Ethernet";
    }*/
    
    ///-------Protocol Type------------------------
    stringstream protocol_stream;
    
    current_byte=packet_string[16];
    protocol_stream<<hex<<setw(2)<<setfill('0')<<(unsigned int)current_byte;
    
    current_byte=packet_string[17];
    protocol_stream<<hex<<setw(2)<<setfill('0')<<(unsigned int)current_byte;
    
    binary_string="0x"+protocol_stream.str();
    
    cout<<endl<<"Protocol Type: ";
    verificardE(binary_string);
    
    //printf("0x%02x%02x", (int)ch[0], (int)ch[1]);
    ///-------Hardware Size------------------------
    current_byte=packet_string[18];
    cout<<endl<<"Hardware Size: "<<(unsigned int)current_byte;
    
    ///-------Protocol Size------------------------
    current_byte=packet_string[19];
    cout<<endl<<"Protocol Size: "<<(unsigned int)current_byte;
    
    ///-------OPCODE/request/reply-----------------
    cout<<endl<<"OPCODE: ";
    current_byte=packet_string[21];
    
    if((unsigned int)current_byte==1)
    {
        cout<<(unsigned int)current_byte<<" -> Request";
    }else
    {
        cout<<(unsigned int)current_byte<<" -> Reply";
    }
    
    ///--------Sender Mac----------------------
    cout<<endl<<"Sender Mac: ";
    for(int j=22; j<28; j++)
    {
        current_byte=packet_string[j];
        printf("%02x", (unsigned int)current_byte);
        
        if(j<27)
        {
            cout<<":";
        }
    }

    ///-----------Sender IP---------------------
    cout<<endl<<"Sender IP: ";
    for(int j=28; j<32; j++)
    {
        current_byte=packet_string[j];
        printf("%d", (unsigned int)current_byte);
       
        if(j<31)
        {
            cout<<".";
        }
    }

    ///-----------Tarjet MAC----------------------
    cout<<endl<<"Tarjet Mac: ";
    for(int j=32; j<38; j++)
    {
        current_byte=packet_string[j];
        printf("%02x", (unsigned int)current_byte);
        if(j<37)
        {
            cout<<":";
        }
    }

    ///------------Tarjet IP----------------------
    cout<<endl<<"Tarjet IP: ";
    for(int j=38; j<42; j++)
    {
        current_byte=packet_string[j];
        printf("%d", (unsigned int)current_byte);
        
        if(j<41)
        {
            cout<<".";
        }
    }
}

#endif // ARP_H_INCLUDED
