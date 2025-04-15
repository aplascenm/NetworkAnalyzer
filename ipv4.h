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


int versionIhl(char *c)
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
    cout<<"Version: "<<n<<" ("<<s<<")"<<" -> IPV4";
    for(int i=4; i<8; i++)
    {
        ss2<<c[i];
    }
    s=ss2.str();
    n=strtoull(s.c_str(), &cc, 2);
    cout<<endl<<"IHL: "<<n<<" ("<<n*4<<")";
    return n*4;
}
void dscpEcn(char *c)
{
    string s;
    stringstream ss, ss2;
    int n;
    char *cc;
    for(int i=0; i<6; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    n=strtoull(s.c_str(), &cc, 2);
    cout<<endl<<"DSCP: "<<n;
    if(c[6]=='1')
    {
        cout<<endl<<"ECN bit 1: ON";
    }else
    {
        cout<<endl<<"ECN bit 1: OFF";
    }
    if(c[7]=='1')
    {
        cout<<endl<<"ECN bit 2: ON";
    }else
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
void fragmetsOffset(char *c, char *c2)
{
    string s;
    stringstream ss, ss2;
    int n, n2;
    char *cc;
    for(int i=3; i<8; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    n=strtoull(s.c_str(), &cc, 2);
    for(int i=0; i<8; i++)
    {
        ss2<<c2[i];
    }
    s=ss.str();
    n2=strtoull(s.c_str(), &cc, 2);
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
    int ihl;
    stringstream ss;
    string s;
    char *bin, *bin2;
    unsigned char cb;
    for(unsigned int j=0; j<header->len; j++)
    {
        ss<<buffer[j];
    }
    s=ss.str();

    cout<<endl<<"                IPV4                 "<<endl;
    ///-------MSB Y LSB----------------
    cb=s[14];
    bin=chartobin(cb);
    ihl=versionIhl(bin);
    ///-------DSCP Y ECN---------------
    cb=s[15];
    bin=chartobin(cb);
    dscpEcn(bin);
    ///-------Total Lenght-------------
    long int n,t;
    stringstream z;
    string ss2;
    char *cc;
    cb=s[16];
    bin=chartobin(cb);
    z<<bin;
    cb=s[17];
    bin=chartobin(cb);
    z<<bin;
    ss2=z.str();
    n=strtoull(ss2.c_str(), &cc, 2);
    t=n-20;
    cout<<endl<<"Total Lenght: "<<n;
    ///------Identification------------
    stringstream z2;
    cb=s[18];
    bin=chartobin(cb);
    z2<<bin;
    cb=s[19];
    bin=chartobin(cb);
    z2<<bin;
    ss2=z2.str();
    n=strtoull(ss2.c_str(), &cc, 2);
    cout<<endl<<"Identification: "<<n;
    ///---------FLAGS-------------------
    cb=s[20];
    bin=chartobin(cb);
    flags(bin);
    ///---------Fragment Offset---------
    bin=chartobin(cb);
    cb=s[21];
    bin2=chartobin(cb);
    fragmetsOffset(bin, bin2);
    ///----------Time To Life-----------
    cb=s[22];
    cout<<endl<<"Time to life: "<<(unsigned int)cb;
    ///---------Protocol----------------
    int num;
    stringstream zz2;
    zz2<<(int)s[23];
    ss2=zz2.str();
    num=verificarIPT(ss2);
    ///--------Header Checksum----------
    stringstream sss;
    string sz;
    cb=s[24];
    sss<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    cb=s[25];
    sss<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    sz="0x"+sss.str();
    cout<<endl<<"Header Checksum: "<<sz;
    ///---------Direccion Origen-----------
    cout<<endl<<"Sender IP: ";
    for(int j=26; j<30; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<29)
        {
            cout<<".";
        }
    }
    ///---------Direccion Destino----------
    cout<<endl<<"Tarjet IP: ";
    for(int j=30; j<34; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<33)
        {
            cout<<".";
        }
    }
    ///-----------Data----------------------
    identificar(num, header, buffer,t);
}
#endif // IPV4_H_INCLUDED
