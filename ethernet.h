#ifndef ETHERNET_H_INCLUDED
#define ETHERNET_H_INCLUDED
#include <pcap.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <limits.h>
#include <iomanip>
#include "diccionario.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
using namespace std;

/*char* chartobin ( unsigned char c )
{
    static char bin[CHAR_BIT + 1] = { 0 };
    int i;

    for ( i = CHAR_BIT - 1; i >= 0; i-- )
    {
        bin[i] = (c % 2) + '0';
        c /= 2;
    }

    return bin;
}*/

void cast (char *c)
{
    if(c[7]=='1')
    {
        cout<<" Es Multicast";
    }
    if(c[7]=='0')
    {
        cout<<" Es Unicast ";
    }
}

void ethernet(const struct pcap_pkthdr *header, const u_char *buffer)
{
    stringstream ss;
    string s;
    char *bin;
    unsigned char cb;
    for(unsigned int j=0; j<header->len; j++)
    {
        ss<<buffer[j];
    }
    s=ss.str();

    //Direcciones MAC:
    cout<<endl;
    cout<<"Direccion Destino: ";
    for(int j=0; j<6; j++)
    {
        cb=s[j];
        if(j==0)
        {
            bin=chartobin(cb);
        }
        printf("%02x", (int)cb);
        if(j==5)
        {
            cout<<" ->";
        }else
        {
            cout<<":";
        }
    }
    cast(bin);
    cout<<endl;
    cout<<"Direccion Origen: ";
    for(int j=6; j<12; j++)
    {
        cb=s[j];
        if(j==6)
        {
            bin=chartobin(cb);
        }
        printf("%02x", (int)cb);
        if(j==11)
        {
            cout<<" ->";
        }else
        {
            cout<<":";
        }
    }
    cast(bin);
    //Tipo
    stringstream z;
    string s2;
    cb=s[12];
    z<<hex<<setw(2)<<setfill('0')<<(int)cb;
    cb=s[13];
    z<<hex<<setw(2)<<setfill('0')<<(int)cb;
    s2="0x"+z.str();
    cout<<endl<<"Tipo: ";
    verificardE(s2);
    //Carga util
    cout<<endl<<"Hay "<<header->len-14<<" Bytes de carga util.";
    //Carga
    cout<<endl;
    for(int i=0; i<100; i++)
    {
        if(dEthertype[i]==s2)
        {
            if(dEthertype[i+2]=="ARP")
            {
                ///------------ARP----------------------------------
                arp(header, buffer);
            }
            if(dEthertype[i+2]=="IPV4")
            {
                ///------------IPV4----------------------------------
                ipv4(header, buffer);
            }
            if(dEthertype[i+2]=="IPV6")
            {
                ///------------IPV6----------------------------------
                ipv6(header, buffer);
            }
        }
    }
}

#endif // ETHERNET_H_INCLUDED
