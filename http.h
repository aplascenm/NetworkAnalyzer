#ifndef HTTP_H_INCLUDED
#define HTTP_H_INCLUDED
#include <iostream>
#include "diccionario.h"

using namespace std;

void http(const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned char current_byte;
    stringstream packet_stream;
    string packet_string;

    for(unsigned int j=0; j<header->len; j++)
    {
            packet_stream<<buffer[j];
    }

    packet_string=packet_stream.str();

    //
    char *bin;
    
    cout<<endl<<endl<<"                HTTP                "<<endl;
    
    //Type
    string http_line;
    stringstream http_stream;
    char current_char;
    long int current_position;

    current_position=74;
    current_char=packet_string[current_position];
    
    while(current_char!='/r')
    {
        current_byte=packet_string[current_position];
        if((unsigned int)current_byte==13)
        {
            break;
        }
        http_stream<<packet_string[current_position];
        current_position++;
        current_char=packet_string[current_position];
    }

    http_line=http_stream.str();

    cout<<endl<<"Es un: "<<http_line;
}

#endif // HTTP_H_INCLUDED
