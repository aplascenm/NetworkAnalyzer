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

void versionipv6(char *c)
{
    string s;
    stringstream ss, ss2;
    int n;
    char *cc;
    for(int i=0; i<4; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    n=strtoull(s.c_str(), &cc, 2);
    cout<<"Version: "<<n<<" ("<<s<<")"<<" -> IPV6";
}
void trafficClass(char *c, char *c2)
{
    string s,s2;
    stringstream ss, ss2;
    int n, n2;
    char *cc;
    for(int i=4; i<8; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    n=strtoull(s.c_str(), &cc, 2);

    for(int i=0; i<4; i++)
    {
        ss2<<c2[i];
    }
    s2=ss2.str();
    n2=strtoull(s.c_str(), &cc, 2);
    printf("\nTraffic Class: 0x%02x%02x",n, n2);
}
void flowLabel(char *c, char *c2, char *c3)
{
    string s,z;
    stringstream ss, ss2, ss3,zz;
    unsigned long int n;
    char *cc;
    for(int i=4; i<8; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    ///n=strtoull(s.c_str(), &cc, 2);
    zz<<s;
    for(int i=0; i<8; i++)
    {
        ss2<<c2[i];
    }
    s=ss2.str();
    zz<<s;
    ///n=strtoull(s.c_str(), &cc, 2);
    for(int i=0; i<8; i++)
    {
        ss3<<c3[i];
    }
    s=ss3.str();
    zz<<s;
    z=zz.str();
    n=strtoull(z.c_str(), &cc, 2);
    cout<<endl<<"Flow Label: "<<n;
}

void ipv6(const struct pcap_pkthdr *header, const u_char *buffer)
{
    int tam;
    unsigned char cb;
    stringstream ss;
    string s;
    for(unsigned int j=0; j<header->len; j++)
    {
        ss<<buffer[j];
    }
    s=ss.str();
    cout<<endl<<"                IPV6                 "<<endl;
    char *bin, *bin2, *bin3;
    ///-------------version---------------------
    cb=s[14];
    bin=chartobin(cb);
    versionipv6(bin);
    ///----------Traffic class-------------------
    cb=s[14];
    bin=chartobin(cb);
    cb=s[15];
    bin2=chartobin(cb);
    trafficClass(bin, bin2);
    ///----------Flow Label-----------------------
    cb=s[15];
    bin=chartobin(cb);
    cb=s[16];
    bin2=chartobin(cb);
    cb=s[17];
    bin3=chartobin(cb);
    flowLabel(bin, bin2, bin3);
    ///----------Payload Lenght-------------------
    char *cc;
    long int n, t;
    stringstream s1,z;
    string s2;
    cb=s[18];
    bin=chartobin(cb);
    s1<<bin;
    cb=s[19];
    bin=chartobin(cb);
    s1<<bin;
    s2=s1.str();
    n=strtoull(s2.c_str(), &cc, 2);
    t=n-40;
    cout<<endl<<"Payload Lenght: "<<n;
    ///----------Next Header-------------------
    int num;
    stringstream ss1;
    cb=s[20];
    ss1<<(unsigned int)cb;
    s2=ss1.str();
    num=verificarIPT6(s2);
    ///----------Hop Limit---------------------
    cb=s[21];
    cout<<endl<<"Hop Limit: "<<(unsigned int)cb;
    ///----------Source address----------------
    cout<<endl<<"Source Address: ";
    int cont=0;
    for(int j=22; j<38; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        cont++;
        if(j<37)
        {
            if(cont==2)
            {
            cont=0;
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
    cont=0;
    for(int j=38; j<54; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        cont++;
        if(j<53)
        {
            if(cont==2)
            {
            cont=0;
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
    if(num==58)
    {
        icmp6(header, buffer, t);
    }else if(num==17)
    {
        udp(header,buffer,6);
    }else if(num==6)
    {
        tcp(header, buffer, 6);
    }
}

#endif // IPV6_H_INCLUDED
