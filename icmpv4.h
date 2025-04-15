#ifndef ICMP_H_INCLUDED
#define ICMP_H_INCLUDED
#include <iostream>
#include "diccionario.h"

using namespace std;


void icmp4 (const struct pcap_pkthdr *header, const u_char *buffer,int t)
{
    int ident;
    int tam;
    string s;
    char *bin, *cc;
    unsigned char cb;
    stringstream ss;
    for(unsigned int j=0; j<header->len; j++)
    {
        ss<<buffer[j];
    }
    s=ss.str();
    cout<<endl<<endl<<"                ICMPV4                 "<<endl;
    ///----------------TYPE, CODE-----------------------
    cb=s[34];
    stringstream s1;
    string s2;
    s1<<(unsigned int)cb;
    if((unsigned int)cb==3||(unsigned int)cb==5||(unsigned int)cb==11)
    {
        cb=s[35];
        s1<<"-"<<(unsigned int)cb;
    }else{
        s1<<"-0";
    }
    s2=s1.str();
    ident=verificarIcmp4(s2);
    ///---------------Checksum----------------------------
    stringstream ss1;
    cb=s[36];
    ss1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    cb=s[37];
    ss1<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    s2="0x"+ss1.str();
    cout<<endl<<"Header Checksum: "<<s2;
    if(ident==0||ident==8)
    {
        ///--------------Identificador-------------------------
        long int n;
        stringstream z;
        cb=s[38];
        bin=chartobin(cb);
        z<<bin;
        cb=s[39];
        bin=chartobin(cb);
        z<<bin;
        s2=z.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Identificador: "<<n;
        ///--------------Secuencia------------------------------
        stringstream z1;
        cb=s[40];
        bin=chartobin(cb);
        z1<<bin;
        cb=s[41];
        bin=chartobin(cb);
        z1<<bin;
        s2=z1.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Numero de Secuencia: "<<n;
        ///------------------Payload-----------------------------
        cout<<endl<<"Payload Lenght: "<<t-8;
    }else if(ident==3)
    {
        cout<<endl<<"Payload Lenght: "<<t-4;
    }else if(ident==5)
    {
        ///--------------Gateway---------------------------------
        cout<<endl<<"Gateway: ";
        for(int j=38; j<42; j++)
        {
            cb=s[j];
            printf("%d", (unsigned int)cb);
            if(j<41)
            {
                cout<<".";
            }
        }
        ///------------Payload------------------------------------
        cout<<endl<<"Payload Lenght: "<<t-8;
    }else if(ident==1)
    {
        cout<<endl<<"Payload Lenght: "<<t-4;
    }
}
#endif // ICMP_H_INCLUDED
