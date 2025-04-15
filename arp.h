#ifndef ARP_H_INCLUDED
#define ARP_H_INCLUDED
#include <iostream>
#include "diccionario.h"
using namespace std;


void arp (const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned char cb;
    stringstream ss;
    string s;
    for(unsigned int j=0; j<header->len; j++)
    {
        ss<<buffer[j];
    }
    s=ss.str();
    cout<<endl<<"                ARP                 "<<endl;
    ///-------Hardware type------------------------
    char *bin, *cc;
    long int n;
    string s2;
    stringstream ss2,z;
    cb=s[14];
    bin=chartobin(cb);
    ss2<<bin;
    cb=s[15];
    bin=chartobin(cb);
    ss2<<bin;
    s2=ss2.str();
    n=strtoull(s2.c_str(), &cc, 2);
    z<<n;
    s2=z.str();
    verificarHT(s2);
    //cout<<endl<<"Hardware Type: "<<s;
    /*cout<<endl<<"Hardware Type: "<<(int)ch[0];
    if((int)ch[0]==1)
    {
        cout<<" -> Ethernet";
    }*/
    ///-------Protocol Type------------------------
    stringstream s1;
    cb=s[16];
    s1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    cb=s[17];
    s1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    s2="0x"+s1.str();
    cout<<endl<<"Protocol Type: ";
    verificardE(s2);
    //printf("0x%02x%02x", (int)ch[0], (int)ch[1]);
    ///-------Hardware Size------------------------
    cb=s[18];
    cout<<endl<<"Hardware Size: "<<(unsigned int)cb;
    ///-------Protocol Size------------------------
    cb=s[19];
    cout<<endl<<"Protocol Size: "<<(unsigned int)cb;
    ///-------OPCODE/request/reply-----------------
    cout<<endl<<"OPCODE: ";
    cb=s[21];
    if((unsigned int)cb==1)
    {
        cout<<(unsigned int)cb<<" -> Request";
    }else
    {
        cout<<(unsigned int)cb<<" -> Reply";
    }
    ///--------Sender Mac----------------------
    cout<<endl<<"Sender Mac: ";
    for(int j=22; j<28; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        if(j<27)
        {
            cout<<":";
        }
    }
    ///-----------Sender IP---------------------
    cout<<endl<<"Sender IP: ";
    for(int j=28; j<32; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<31)
        {
            cout<<".";
        }
    }
    ///-----------Tarjet MAC----------------------
    cout<<endl<<"Tarjet Mac: ";
    for(int j=32; j<38; j++)
    {
        cb=s[j];
        printf("%02x", (unsigned int)cb);
        if(j<37)
        {
            cout<<":";
        }
    }
    ///------------Tarjet IP----------------------
    cout<<endl<<"Tarjet IP: ";
    for(int j=38; j<42; j++)
    {
        cb=s[j];
        printf("%d", (unsigned int)cb);
        if(j<41)
        {
            cout<<".";
        }
    }
}
#endif // ARP_H_INCLUDED
