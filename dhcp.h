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

void dhcpop(string s, long int pos)
{
    string s2;
    char *bin, *cc;
    unsigned char cb;
    cb=s[pos];
    unsigned int ui=(unsigned int)cb;
    if(ui==255)
    {
        cout<<endl<<"Code: 255 -> Fin de Opciones.";
        return;
    }else if(ui==4)
    {
        cout<<endl<<"Code: 4 -> Time Server Option.";
        pos++;
        //Len
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
    }else if(ui==12)
    {
        cout<<endl<<"Code: 12 -> Host Name Option.";
        pos++;
        //Len
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
    }else if(ui==15)
    {
        cout<<endl<<"Code: 15 -> Domain Name Option.";
        pos++;
        //Len
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
    }else if(ui==51)
    {
        cout<<endl<<"Code: 51 -> IP Address Lease Time Option.";
        pos++;
        //Len
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
        //Lease Time
        double nn;
        long int n;
        stringstream z;
        string s2;
        cb=s[pos];
        pos++;
        bin=chartobin(cb);
        z<<bin;
        cb=s[pos];
        pos++;
        bin=chartobin(cb);
        z<<bin;
        cb=s[pos];
        pos++;
        bin=chartobin(cb);
        z<<bin;
        cb=s[pos];
        pos++;
        bin=chartobin(cb);
        z<<bin;
        s2=z.str();
        n=strtoull(s2.c_str(), &cc, 2);
        nn=(n/60)/60;
        cout<<endl<<"Lease Time: "<<n<<"S. ("<<nn<<" H.)";
    }else if(ui==53)
    {
        cout<<endl<<"Code: 53 -> DHCP Message Type Option.";
        pos++;
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
        cb=s[pos];
        stringstream mt;
        mt<<(unsigned int)cb;
        s2=mt.str();
        for(int j=0; j<9; j++)
        {
            if(s2==dhcpmt[j])
            {
                cout<<endl<<"Value: "<<s2<<" -> "<<dhcpmt[j+1];
            }
        }
    }else if(ui==54)
    {
        cout<<endl<<"Code: 54 -> Server Identifier Option.";
        pos++;
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
        cout<<endl<<"Address: ";
        for(int j=pos; j<pos+4; j++)
        {
            cb=s[j];
            printf("%d", (unsigned int)cb);
            if(j<pos+3)
            {
                cout<<".";
            }
        }
    }else if(ui==55)
    {
        cout<<endl<<"Code: 54 -> Server Identifier Option.";
        pos++;
        cb=s[pos];
        cout<<endl<<"LEN: "<<(unsigned int)cb;
        pos++;
    }else
    {
        cout<<endl<<"No Encontrado";
        return;
    }
    dhcpop(s, pos);
}

void dhcp(const struct pcap_pkthdr *header, const u_char *buffer, int tp)
{
    unsigned char cb;
    stringstream ss;
    string s;
    for(unsigned int j=0; j<header->len; j++)
    {
            ss<<buffer[j];
    }
    s=ss.str();
    ///
    char *bin;
    cout<<endl<<endl<<"                DHCP - IPV4                 "<<endl;
    //Message Type
    cb=s[42];
    cout<<endl<<"Message Type: "<<(unsigned int)cb;if((unsigned int)cb==1){cout<<"-> Request";}else{"-> Reply";}
    //Hardware Type
    cb=s[43];
    cout<<endl<<"Hardware Type: "<<(unsigned int)cb;if((unsigned int)cb==1){cout<<"-> Ethernet";}
    //Hardware Address Length
    cb=s[44];
    cout<<endl<<"Hardware Address Length: "<<(unsigned int)cb;
    //Hops
    cb=s[45];
    cout<<endl<<"Hops: "<<(unsigned int)cb;
    //Transaction ID
    long long int n;
    stringstream z;
    string s2;
    char *cc;
    cb=s[46];
    bin=chartobin(cb);
    z<<bin;
    cb=s[47];
    bin=chartobin(cb);
    z<<bin;
    cb=s[48];
    bin=chartobin(cb);
    z<<bin;
    cb=s[49];
    bin=chartobin(cb);
    z<<bin;
    s2=z.str();
    n=strtoull(s2.c_str(), &cc, 2);
    cout<<endl<<"Transaction ID: "<<n;
    //Seconds Elapsed
    stringstream z1;
    cb=s[50];
    bin=chartobin(cb);
    z<<bin;
    cb=s[51];
    bin=chartobin(cb);
    z<<bin;
    s2=z.str();
    n=strtoull(s2.c_str(), &cc, 2);
    cout<<endl<<"Seconds Elapsed: "<<n;
    //Flag(s)
    cb=s[52];
    bin=chartobin(cb);
    fla(bin);
    //Client Address
    cout<<endl<<"Client Address: ";
    for(int j=54; j<58; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<57)
        {
            cout<<".";
        }
    }
    //Your Client Address
    cout<<endl<<"Your Client Address: ";
    for(int j=58; j<62; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<61)
        {
            cout<<".";
        }
    }
    //Next Server IP
    cout<<endl<<"Next Server IP: ";
    for(int j=62; j<66; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<65)
        {
            cout<<".";
        }
    }
    //Relay Agent IP
    cout<<endl<<"Relay Agent IP: ";
    for(int j=66; j<70; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<69)
        {
            cout<<".";
        }
    }
    //Client Mac Address
    cout<<endl<<"Client Mac Address: ";
    for(int j=70; j<76; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
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
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        if(j<149)
        {
            cout<<" ";
        }
    }
    //Boot File
    cout<<endl<<"Boot File: ";
    for(int j=150; j<278; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        if(j<277)
        {
            cout<<" ";
        }
    }
    //Magic Cookie
    cout<<endl<<"Magic Cookie: ";
    for(int j=278; j<282; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        if(j<281)
        {
            cout<<" ";
        }
    }
    //Options
    dhcpop(s, 282);
}

#endif // DHCP_H_INCLUDED
