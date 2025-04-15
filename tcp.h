#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED
#include <iostream>
#include "diccionario.h"
#include "http.h"
using namespace std;


void dataresns(char *c)
{
    //Data Offset
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
    cout<<endl<<"Data offset: "<<n<<" ->"<<s<<" ("<<n*4<<")";
    //Reserved
    for(int i=5; i<7; i++)
    {
        ss2<<c[i];
    }
    s=ss2.str();
    n=strtoull(s.c_str(), &cc, 2);
    cout<<endl<<"Reserved Bits: "<<n;
    //Bandera NS
    if(c[7]=='1')
    {
        cout<<endl<<"Bandera NS: ON";
    }else
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
    int tam;
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
        cout<<endl<<endl<<"                TCP - IPV4                 "<<endl;
        char *bin;
        //Source Port
        long int ns, nd;
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
        ns=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Source Port: "<<ns;
        //Destination Port
        stringstream z1;
        cb=s[36];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[37];
        bin=chartobin(cb);
        z1<<bin;
        ss2=z1.str();
        nd=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Destination Port: "<<nd;
        //Seq Number
        long long int nn;
        stringstream z2;
        cb=s[38];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[39];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[40];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[41];
        bin=chartobin(cb);
        z2<<bin;
        ss2=z2.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Seq Number: "<<nn;
        //Ack Number
        stringstream z3;
        cb=s[42];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[43];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[44];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[45];
        bin=chartobin(cb);
        z3<<bin;
        ss2=z3.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Ack Number: "<<nn;
        //Data Offset
        cb=s[46];
        bin=chartobin(cb);
        dataresns(bin);
        //Flags
        cb=s[47];
        bin=chartobin(cb);
        flagst(bin);
        //Windows Size
        stringstream z4;
        cb=s[48];
        bin=chartobin(cb);
        z4<<bin;
        cb=s[49];
        bin=chartobin(cb);
        z4<<bin;
        ss2=z4.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Windows Size: "<<nn;
        //Checksum
        stringstream z5;
        cb=s[50];
        z5<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        cb=s[51];
        z5<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        ss2="0x"+z5.str();
        cout<<endl<<"Checksum: "<<ss2;
        //Urgen Pointer
        stringstream z6;
        cb=s[52];
        bin=chartobin(cb);
        z6<<bin;
        cb=s[53];
        bin=chartobin(cb);
        z6<<bin;
        ss2=z6.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Urgent Pointer: "<<nn;
        //
        if(ns==80||nd==80)
        {
            http(header, buffer);
        }
    }else
    {
        cout<<endl<<endl<<"                TCP - IPV6                 "<<endl;
        char *bin;
        //Source Port
        long int n;
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
        n=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Source Port: "<<n;
        //Destination Port
        stringstream z1;
        cb=s[56];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[57];
        bin=chartobin(cb);
        z1<<bin;
        ss2=z1.str();
        n=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Destination Port: "<<n;
        //Seq Number
        long long int nn;
        stringstream z2;
        cb=s[58];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[59];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[60];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[61];
        bin=chartobin(cb);
        z2<<bin;
        ss2=z2.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Seq Number: "<<nn;
        //Ack Number
        stringstream z3;
        cb=s[62];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[63];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[64];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[65];
        bin=chartobin(cb);
        z3<<bin;
        ss2=z3.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Ack Number: "<<nn;
        //Data Offset
        cb=s[66];
        bin=chartobin(cb);
        dataresns(bin);
        //Flags
        cb=s[67];
        bin=chartobin(cb);
        flagst(bin);
        //Windows Size
        stringstream z4;
        cb=s[68];
        bin=chartobin(cb);
        z4<<bin;
        cb=s[69];
        bin=chartobin(cb);
        z4<<bin;
        ss2=z4.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Windows Size: "<<nn;
        //Checksum
        stringstream z5;
        cb=s[70];
        z5<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        cb=s[71];
        z5<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
        ss2="0x"+z5.str();
        cout<<endl<<"Checksum: "<<ss2;
        //Urgen Pointer
        stringstream z6;
        cb=s[72];
        bin=chartobin(cb);
        z6<<bin;
        cb=s[73];
        bin=chartobin(cb);
        z6<<bin;
        ss2=z6.str();
        nn=strtoull(ss2.c_str(), &cc, 2);
        cout<<endl<<"Urgent Pointer: "<<nn;
    }
}

#endif // TCP_H_INCLUDED
