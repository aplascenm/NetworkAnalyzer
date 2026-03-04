#ifndef ICMP_H_INCLUDED
#define ICMP_H_INCLUDED
#include <iostream>
#include "diccionario.h"

using namespace std;


void icmp4 (const struct pcap_pkthdr *header, const u_char *buffer,int length)
{
    int icmp_identifier;
    int payload_size;
    string packet_string;
    char *bin, *end_ptr;
    unsigned char current_byte;
    stringstream packet_stream;

    for(unsigned int j=0; j<header->len; j++)
    {
        packet_stream<<buffer[j];
    }

    packet_string=packet_stream.str();

    cout<<endl<<endl<<"                ICMPV4                 "<<endl;
    
    ///----------------TYPE, CODE-----------------------
    current_byte=packet_string[34];

    stringstream type_code_stream;
    string type_code_string;

    type_code_stream<<(unsigned int)current_byte;

    if((unsigned int)current_byte==3||(unsigned int)current_byte==5||(unsigned int)current_byte==11)
    {
        current_byte=packet_string[35];
        type_code_stream<<"-"<<(unsigned int)current_byte;
    }else{
        type_code_stream<<"-0";
    }

    type_code_string=type_code_stream.str();
    icmp_identifier=verificarIcmp4(type_code_string);

    ///---------------Checksum----------------------------
    stringstream checksum_stream;

    current_byte=packet_string[36];
    checksum_stream<<hex<<setw(2)<<setfill('0')<<(unsigned int)current_byte;
    
    current_byte=packet_string[37];
    checksum_stream<<hex<<setw(2)<<setfill('0')<<(unsigned int)current_byte;
    
    type_code_string="0x"+checksum_stream.str();
    cout<<endl<<"Header Checksum: "<<type_code_string;
    
    if(icmp_identifier==0||icmp_identifier==8)
    {
        ///--------------Identificador-------------------------
        long int n;
        stringstream identifier_stream;
        
        current_byte=packet_string[38];
        bin=chartobin(current_byte);
        identifier_stream<<bin;
        
        current_byte=packet_string[39];
        bin=chartobin(current_byte);
        identifier_stream<<bin;
        
        type_code_string=identifier_stream.str();
        n=strtoull(type_code_string.c_str(), &end_ptr, 2);
        
        cout<<endl<<"Identificador: "<<n;
        
        ///--------------Secuencia------------------------------
        stringstream sequence_stream;

        current_byte=packet_string[40];
        bin=chartobin(current_byte);
        sequence_stream<<bin;

        current_byte=packet_string[41];
        bin=chartobin(current_byte);
        sequence_stream<<bin;

        type_code_string=sequence_stream.str();
        n=strtoull(type_code_string.c_str(), &end_ptr, 2);

        cout<<endl<<"Numero de Secuencia: "<<n;
        
        ///------------------Payload-----------------------------
        cout<<endl<<"Payload Lenght: "<<length-8;
    }
    else if(icmp_identifier==3)
    {
        cout<<endl<<"Payload Lenght: "<<length-4;
    }
    else if(icmp_identifier==5)
    {
        ///--------------Gateway---------------------------------
        cout<<endl<<"Gateway: ";
        
        for(int j=38; j<42; j++)
        {
            current_byte=packet_string[j];
            printf("%d", (unsigned int)current_byte);
            if(j<41)
            {
                cout<<".";
            }
        }

        ///------------Payload------------------------------------
        cout<<endl<<"Payload Lenght: "<<length-8;
    }else if(icmp_identifier==1)
    {
        cout<<endl<<"Payload Lenght: "<<length-4;
    }
}

#endif // ICMP_H_INCLUDED
