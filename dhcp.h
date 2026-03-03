#ifndef DHCP_H_INCLUDED
#define DHCP_H_INCLUDED
#include <iostream>
//#include <string.h>
//#include <sstream>
#include "diccionario.h"

using namespace std;

void fla(char *c)
{
    if(c[0]=='0')
    {
        cout<<endl<<"MSB: 0 -> Unicast";
    }else
    {
        cout<<endl<<"MSB: 1 -> Multicast";
    }
}

void dhcpop(string packet_string, long int current_position)
{
    string value_string;
    char *binary_ptr, *end_ptr;
    unsigned char current_byte;
    
    current_byte=packet_string[current_position];
    unsigned int option_code=(unsigned int)current_byte;
    
    if(option_code==255)
    {
        cout<<endl<<"Code: 255 -> Fin de Opciones.";
        return;
    }
    else if(option_code==4)
    {
        cout<<endl<<"Code: 4 -> Time Server Option.";
        current_position++;
        
        //Len
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
    }
    else if(option_code==12)
    {
        cout<<endl<<"Code: 12 -> Host Name Option.";
        current_position++;
        
        //Len
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
    }
    else if(option_code==15)
    {
        cout<<endl<<"Code: 15 -> Domain Name Option.";
        current_position++;
        
        //Len
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
    }
    else if(option_code==51)
    {
        cout<<endl<<"Code: 51 -> IP Address Lease Time Option.";
        current_position++;

        //Len
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
        
        //Lease Time
        double lease_time_hours;
        long int lease_time_seconds;
        stringstream binary_stream;
        string binary_string;

        current_byte=packet_string[current_position];
        current_position++;
        binary_ptr=chartobin(current_byte);
        binary_stream<<binary_ptr;
        
        current_byte=packet_string[current_position];
        current_position++;
        binary_ptr=chartobin(current_byte);
        binary_stream<<binary_ptr;
        
        current_byte=packet_string[current_position];
        current_position++;
        binary_ptr=chartobin(current_byte);
        binary_stream<<binary_ptr;
        
        current_byte=packet_string[current_position];
        current_position++;
        binary_ptr=chartobin(current_byte);
        binary_stream<<binary_ptr;

        binary_string=binary_stream.str();
        lease_time_seconds=strtoull(binary_string.c_str(), &end_ptr, 2);
        lease_time_hours=(lease_time_seconds/60)/60;
        
        cout<<endl<<"Lease Time: "<<lease_time_seconds<<"S. ("<<lease_time_hours<<" H.)";
    }
    else if(option_code==53)
    {
        cout<<endl<<"Code: 53 -> DHCP Message Type Option.";
        current_position++;
        
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
        
        current_byte=packet_string[current_position];

        stringstream message_type_stream;
        message_type_stream<<(unsigned int)current_byte;
        value_string=message_type_stream.str();
        
        for(int j=0; j<9; j++)
        {
            if(value_string==dhcpmt[j])
            {
                cout<<endl<<"Value: "<<value_string<<" -> "<<dhcpmt[j+1];
            }
        }
    }
    else if(option_code==54)
    {
        cout<<endl<<"Code: 54 -> Server Identifier Option.";
        current_position++;
        
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
        
        cout<<endl<<"Address: ";
        for(int j=current_position; j<current_position+4; j++)
        {
            current_byte=packet_string[j];
            printf("%d", (unsigned int)current_byte);
            if(j<current_position+3)
            {
                cout<<".";
            }
        }
    }
    else if(option_code==55)
    {
        cout<<endl<<"Code: 55 -> Parameter Request List Option.";
        current_position++;
        
        current_byte=packet_string[current_position];
        cout<<endl<<"LEN: "<<(unsigned int)current_byte;
        current_position++;
    }else
    {
        cout<<endl<<"No Encontrado";
        return;
    }

    dhcpop(packet_string, current_position);
}

void dhcp(const struct pcap_pkthdr *packet_header, const u_char *packet_buffer, int transport_protocol)
{
    unsigned char current_byte;
    stringstream packet_stream;
    string packet_string;

    for(unsigned int j=0; j<packet_header->len; j++)
    {
            packet_stream<<packet_buffer[j];
    }
    packet_string=packet_stream.str();

    ///
    char *binary_ptr;
    cout<<endl<<endl<<"                DHCP - IPV4                 "<<endl;
    
    //Message Type
    current_byte=packet_string[42];
    cout<<endl<<"Message Type: "<<(unsigned int)current_byte;
    if((unsigned int)current_byte==1){cout<<"-> Request";}else{"-> Reply";}
    
    //Hardware Type
    current_byte=packet_string[43];
    cout<<endl<<"Hardware Type: "<<(unsigned int)current_byte;
    if((unsigned int)current_byte==1){cout<<"-> Ethernet";}
    
    //Hardware Address Length
    current_byte=packet_string[44];
    cout<<endl<<"Hardware Address Length: "<<(unsigned int)current_byte;
    
    //Hops
    current_byte=packet_string[45];
    cout<<endl<<"Hops: "<<(unsigned int)current_byte;
    
    //Transaction ID
    long long int transaction_id;
    stringstream binary_stream;
    string binary_string;
    char *end_ptr;

    current_byte=packet_string[46];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;
    
    current_byte=packet_string[47];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;
    
    current_byte=packet_string[48];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;
    
    current_byte=packet_string[49];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;
    
    binary_string=binary_stream.str();
    transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
    cout<<endl<<"Transaction ID: "<<transaction_id;

    //Seconds Elapsed
    stringstream seconds_stream;

    current_byte=packet_string[50];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;

    current_byte=packet_string[51];
    binary_ptr=chartobin(current_byte);
    binary_stream<<binary_ptr;

    binary_string=binary_stream.str();
    transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
    cout<<endl<<"Seconds Elapsed: "<<transaction_id;

    //Flag(s)
    current_byte=packet_string[52];
    binary_ptr=chartobin(current_byte);
    fla(binary_ptr);

    //Client Address
    cout<<endl<<"Client Address: ";
    for(int j=54; j<58; j++)
    {
        current_byte=packet_string[j];
        printf("%d", (unsigned int)current_byte);
        if(j<57)
        {
            cout<<".";
        }
    }

    //Your Client Address
    cout<<endl<<"Your Client Address: ";
    for(int j=58; j<62; j++)
    {
        current_byte=packet_string[j];
        printf("%d", (unsigned int)current_byte);
        if(j<61)
        {
            cout<<".";
        }
    }

    //Next Server IP
    cout<<endl<<"Next Server IP: ";
    for(int j=62; j<66; j++)
    {
        current_byte=packet_string[j];
        printf("%d", (unsigned int)current_byte);
        if(j<65)
        {
            cout<<".";
        }
    }

    //Relay Agent IP
    cout<<endl<<"Relay Agent IP: ";
    for(int j=66; j<70; j++)
    {
        current_byte=packet_string[j];
        printf("%d", (unsigned int)current_byte);
        if(j<69)
        {
            cout<<".";
        }
    }

    //Client Mac Address
    cout<<endl<<"Client Mac Address: ";
    for(int j=70; j<76; j++)
    {
        current_byte=packet_string[j];
        printf("%02x", (unsigned int)current_byte);
        if(j<75)
        {
            cout<<":";
        }
    }

    //10 Bytes Padding
    //Server Host Name
    cout<<endl<<"Server Host Name: ";
    for(int j=86; j<150; j++)
    {
        current_byte=packet_string[j];
        printf("%02x", (unsigned int)current_byte);
        if(j<149)
        {
            cout<<" ";
        }
    }

    //Boot File
    cout<<endl<<"Boot File: ";
    for(int j=150; j<278; j++)
    {
        current_byte=packet_string[j];
        printf("%02x", (unsigned int)current_byte);
        if(j<277)
        {
            cout<<" ";
        }
    }

    //Magic Cookie
    cout<<endl<<"Magic Cookie: ";
    for(int j=278; j<282; j++)
    {
        current_byte=packet_string[j];
        printf("%02x", (unsigned int)current_byte);
        if(j<281)
        {
            cout<<" ";
        }
    }
    
    //Options
    dhcpop(packet_string, 282);
}

#endif // DHCP_H_INCLUDED
