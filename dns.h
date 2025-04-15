#ifndef DNS_H_INCLUDED
#define DNS_H_INCLUDED
#include <iostream>
#include "diccionario.h"


void flagsdns(char *c)
{
    string s;
    stringstream ss;
    int n;
    char *cc;
    if(c[0]=='0')
    {
        cout<<endl<<"0... .... .... .... = Query";
    }else
    {
        cout<<endl<<"1... .... .... .... = Response";
    }
    for(int i=1; i<5; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    for(int j=0; j<8; j++)
    {
        if(s==flagsdns1[j])
        {
            cout<<endl<<flagsdns1[j+1];
        }
    }

    if(c[5]=='0')
    {
        cout<<endl<<".... .0.. .... .... = Non-authoritative DNS answer";
    }else
    {
        cout<<endl<<".... .1.. .... .... = Authoritative DNS answer";
    }

    if(c[6]=='0')
    {
        cout<<endl<<".... ..0. .... .... = Message not truncated";
    }else
    {
        cout<<endl<<".... ..1. .... .... = Message truncated";
    }

    if(c[7]=='0')
    {
        cout<<endl<<".... ...0 .... .... = Non-recursive Query";
    }else
    {
        cout<<endl<<".... ...1 .... .... = Recursive Query";
    }
}

void flagsdns2(char *c)
{
    string s;
    stringstream ss;
    int n;
    char *cc;
    if(c[0]=='0')
    {
        cout<<endl<<".... .... 0... .... = Recursion not available";
    }else
    {
        cout<<endl<<".... .... 1... .... = Recursive available";
    }

    if(c[2]=='0')
    {
        cout<<endl<<".... .... .0.. .... = Authority portion was not authenticated by the server";
    }else
    {
        cout<<endl<<".... .... .1.. .... = Authority portion was authenticated by the server";
    }

    for(int i=4; i<8; i++)
    {
        ss<<c[i];
    }
    s=ss.str();
    for(int j=0; j<8; j++)
    {
        if(s==flagsdns22[j])
        {
            cout<<endl<<flagsdns22[j+1];
        }
    }
}

void dns(const struct pcap_pkthdr *header, const u_char *buffer, int ip, int tp)
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
    if(ip==4)
    {
        cout<<endl<<endl<<"                DNS - IPV4                 "<<endl;
        //Transaction ID
        long int n;
        stringstream z;
        string s2;
        char *cc;
        cb=s[42];
        bin=chartobin(cb);
        z<<bin;
        cb=s[43];
        bin=chartobin(cb);
        z<<bin;
        s2=z.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Transaction ID: "<<n;
        //FLAGS
        //1 byte
        cb=s[44];
        bin=chartobin(cb);
        flagsdns(bin);
        //2 Byte
        cb=s[45];
        bin=chartobin(cb);
        flagsdns2(bin);
        //Questions
        stringstream z1;
        cb=s[46];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[47];
        bin=chartobin(cb);
        z1<<bin;
        s2=z1.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Questions: "<<n;
        //Answers
        stringstream z2;
        cb=s[48];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[49];
        bin=chartobin(cb);
        z2<<bin;
        s2=z2.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Answers RRs: "<<n;
        //Authority
        stringstream z3;
        cb=s[50];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[51];
        bin=chartobin(cb);
        z3<<bin;
        s2=z3.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Authority RRs: "<<n;
        //Additional
        stringstream z4;
        cb=s[52];
        bin=chartobin(cb);
        z4<<bin;
        cb=s[53];
        bin=chartobin(cb);
        z4<<bin;
        s2=z4.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Additional RRs: "<<n;
        //Query
    }else
    {
        cout<<endl<<endl<<"                DNS - IPV6                 "<<endl;
        //Transaction ID
        long int n;
        stringstream z;
        string s2;
        char *cc;
        cb=s[62];
        bin=chartobin(cb);
        z<<bin;
        cb=s[63];
        bin=chartobin(cb);
        z<<bin;
        s2=z.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Transaction ID: "<<n;
        //FLAGS
        //1 byte
        cb=s[64];
        bin=chartobin(cb);
        flagsdns(bin);
        //2 Byte
        cb=s[65];
        bin=chartobin(cb);
        flagsdns2(bin);
        //Questions
        stringstream z1;
        cb=s[66];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[67];
        bin=chartobin(cb);
        z1<<bin;
        s2=z1.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Questions: "<<n;
        //Answers
        stringstream z2;
        cb=s[68];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[69];
        bin=chartobin(cb);
        z2<<bin;
        s2=z2.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Answers RRs: "<<n;
        //Authority
        stringstream z3;
        cb=s[70];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[71];
        bin=chartobin(cb);
        z3<<bin;
        s2=z3.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Authority RRs: "<<n;
        //Additional
        stringstream z4;
        cb=s[72];
        bin=chartobin(cb);
        z4<<bin;
        cb=s[73];
        bin=chartobin(cb);
        z4<<bin;
        s2=z4.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Additional RRs: "<<n;
        //Query
    }
}


#endif // DNS_H_INCLUDED
