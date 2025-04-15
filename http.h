#ifndef HTTP_H_INCLUDED
#define HTTP_H_INCLUDED
#include <iostream>
#include "diccionario.h"

using namespace std;

void http(const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned char cb;
    stringstream ss;
    string s;
    for(unsigned int j=0; j<header->len; j++)
    {
            ss<<buffer[j];
    }
    s=ss.str();
    //
    char *bin;
    cout<<endl<<endl<<"                HTTP                "<<endl;
    //Type
    string m;
    stringstream mm;
    char p;
    long int pos;
    pos=74;
    p=s[pos];
    while(p!='/r')
    {
        cb=s[pos];
        if((unsigned int)cb==13)
        {
            break;
        }
        mm<<s[pos];
        pos++;
        p=s[pos];
    }
    m=mm.str();
    cout<<endl<<"Es un: "<<m;

}

#endif // HTTP_H_INCLUDED
