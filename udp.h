#ifndef UDP_H_INCLUDED
#define UDP_H_INCLUDED
#include <iostream>
#include "diccionario.h"
#include "dns.h"
#include "dhcp.h"
using namespace std;


void udp(const struct pcap_pkthdr *header, const u_char *buffer, int type)
{
    unsigned char cb;
    stringstream ss;
    string s;
    for(unsigned int j=0; j<header->len; j++)
    {
            ss<<buffer[j];
    }
    s=ss.str();
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
        long int n,n1,n2;
        stringstream z;
        string ss2;
        char *cc;
        cb=s[34];
        bin=chartobin(cb);
        z<<bin;
        cb=s[35];
        bin=chartobin(cb);
        z<<bin;
        ss2=z.str();
        n1=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Source Port: "<<n1;
        //Destination Port
        stringstream z1;
        cb=s[36];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[37];
        bin=chartobin(cb);
        z1<<bin;
        ss2=z1.str();
        n2=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Destination Port: "<<n2;
        //Lenght
        stringstream z2;
        cb=s[38];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[39];
        bin=chartobin(cb);
        z2<<bin;
        ss2=z2.str();
        n=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Lenght: "<<n;
        //Checksum
        stringstream ss1;
        cb=s[40];
        ss1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        cb=s[41];
        ss1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        ss2="0x"+ss1.str();
        cout<<endl<<"Header Checksum: "<<ss2;
        //IFDNS
        if(n1==53)
        {
            dns(header, buffer, 4, 1);
        }else if (n2==53)
        {
            dns(header, buffer, 4, 2);
        }

        if(n1==67)
        {
            dhcp(header, buffer, 1);
        }else if(n2==67)
        {
            dhcp(header, buffer, 2);
        }

    }else
    {
        cout<<endl<<endl<<"                UDP - IPV6                 "<<endl;
        char *bin;
        //Source Port
        long int n,n1,n2;
        stringstream z;
        string ss2;
        char *cc;
        cb=s[54];
        bin=chartobin(cb);
        z<<bin;
        cb=s[55];
        bin=chartobin(cb);
        z<<bin;
        ss2=z.str();
        n1=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Source Port: "<<n1;
        //Destination Port
        stringstream z1;
        cb=s[56];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[57];
        bin=chartobin(cb);
        z1<<bin;
        ss2=z1.str();
        n2=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Destination Port: "<<n2;
        //Lenght
        stringstream z2;
        cb=s[58];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[59];
        bin=chartobin(cb);
        z2<<bin;
        ss2=z2.str();
        n=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Lenght: "<<n;
        //Checksum
        stringstream ss1;
        cb=s[60];
        ss1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        cb=s[61];
        ss1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        ss2="0x"+ss1.str();
        cout<<endl<<"Header Checksum: "<<ss2;
        //IFDNS
        if(n1==53)
        {
            dns(header, buffer, 6, 1);
        }else if (n2==53)
        {
            dns(header, buffer, 6, 2);
        }

        if(n1==67)
        {
            dhcp(header, buffer, 1);
        }else if(n2==67)
        {
            dhcp(header, buffer, 2);
        }
    }
}
#endif // UDP_H_INCLUDED
