#ifndef ICMPV6_H_INCLUDED
#define ICMPV6_H_INCLUDED
#include <iostream>
#include "diccionario.h"
using namespace std;

void icmp6 (const struct pcap_pkthdr *header, const u_char *buffer, int t)
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
    cout<<endl<<endl<<"                ICMPV6                 "<<endl;
    int ident;
    ///----------------TYPE, CODE-----------------------
    cb=s[54];
    char *bin, *cc;
    stringstream ss1;
    string s2;
    ss1<<(unsigned int)cb;
    if((unsigned int)cb<10)
    {
        cb=s[55];
        ss1<<"-"<<(unsigned int)cb;
    }else{
        ss1<<"-0";
    }
    s2=ss1.str();
    ident=verificarIcmp6(s2);
    ///---------------Checksum----------------------------
    stringstream sss;
    cb=s[56];
    sss<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    cb=s[57];
    sss<<hex<<setw(2)<<setfill('0')<<(unsigned int)cb;
    s2="0x"+sss.str();
    cout<<endl<<"Header Checksum: "<<s2;
    ///-----------------DATA------------------------------
    if(ident<8)
    {
        //Destination Unreachable Payload
        cout<<endl<<"Payload Lenght: "<<t-8;
    }else if(ident==8||ident==9)
    {
        //Echo Request / Echo Reply
        //Identifier
        long int n;
        stringstream z2;
        cb=s[58];
        bin=chartobin(cb);
        z2<<bin;
        cb=s[59];
        bin=chartobin(cb);
        z2<<bin;
        s2=z2.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Identifier: "<<n;
        //Sequence Number
        stringstream z3;
        cb=s[60];
        bin=chartobin(cb);
        z3<<bin;
        cb=s[61];
        bin=chartobin(cb);
        z3<<bin;
        s2=z3.str();
        n=strtoull(s2.c_str(), &cc, 2);
        cout<<endl<<"Sequence Number: "<<n;
        //Payload
        cout<<endl<<"Payload Lenght: "<<t-12;
    }else if(ident>10)
    {
        if(ident==13)
        {
            //Router Solicitation
            //Type
            cb=s[58];
            cout<<endl<<"Type: "<<(unsigned int)cb;
            if((unsigned int)cb==1)
            {
                cout<<" -> 1 = Source link-layer";
                //Length
                cb=s[59];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=60; j<66; j++)
                {
                    cb=s[j];
                    printf("%02x", (unsigned int)cb);
                    if(j<65)
                    {
                        cout<<":";
                    }
                }
            }else
            {
                cout<<endl<<"No encontrado :v";
            }
        }else if(ident==14)
        {
            //Router Advertisement
            //Cur Hop Limit
            cb=s[58];
            cout<<endl<<"Cur Hop Limit: "<<(unsigned int)cb;
            //Flags
            cb=s[59];
            bin=chartobin(cb);
            if(bin[0]==1)
            {
                cout<<endl<<"Managed Address Flag: ON";
            }else
            {
                cout<<endl<<"Managed Address Flag: OFF";
            }
            if(bin[1]==1)
            {
                cout<<endl<<"Other Configuration Flag: ON";
            }else
            {
                cout<<endl<<"Other Configuration Flag: OFF";
            }
            //Router Lifetime
            double nn;
            long int n;
            stringstream z;
            cb=s[60];
            bin=chartobin(cb);
            z<<bin;
            cb=s[61];
            bin=chartobin(cb);
            z<<bin;
            s2=z.str();
            n=strtoull(s2.c_str(), &cc, 2);
            nn=(n/60)/60;
            cout<<endl<<"Router Lifetime: "<<n<<"S. ("<<nn<<" H.)";
            //Reachable Time
            long long int n1;
            stringstream rl;
            cb=s[62];
            bin=chartobin(cb);
            rl<<bin;
            cb=s[63];
            bin=chartobin(cb);
            rl<<bin;
            cb=s[64];
            bin=chartobin(cb);
            rl<<bin;
            cb=s[65];
            bin=chartobin(cb);
            rl<<bin;
            s2=rl.str();
            n1=strtoull(s2.c_str(), &cc, 2);
            cout<<endl<<"Reachable Time: "<<n1<<" ms.";
            //Retrans Timer
            stringstream rt;
            cb=s[66];
            bin=chartobin(cb);
            rt<<bin;
            cb=s[67];
            bin=chartobin(cb);
            rt<<bin;
            cb=s[68];
            bin=chartobin(cb);
            rt<<bin;
            cb=s[69];
            bin=chartobin(cb);
            rt<<bin;
            s2=rt.str();
            n1=strtoull(s2.c_str(), &cc, 2);
            cout<<endl<<"Retrans Time: "<<n1<<" ms.";
            //Options
            cb=s[70];
            cout<<endl<<"Type: "<<(unsigned int)cb;
            if((unsigned int)cb==1)
            {
                //Source Link-Layer
                cout<<" -> Source Link-Layer.";
                //Length
                cb=s[71];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=72; j<78; j++)
                {
                    cb=s[j];
                    printf("%02x", (unsigned int)cb);
                    if(j<77)
                    {
                        cout<<":";
                    }
                }
            }else if((unsigned int)cb==5)
            {
                //MTU
                cout<<" -> MTU.";
                //Length
                cb=s[71];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //MTU
                long long int n;
                stringstream rt;
                cb=s[72];
                bin=chartobin(cb);
                rt<<bin;
                cb=s[73];
                bin=chartobin(cb);
                rt<<bin;
                cb=s[74];
                bin=chartobin(cb);
                rt<<bin;
                cb=s[75];
                bin=chartobin(cb);
                rt<<bin;
                s2=rt.str();
                n=strtoull(s2.c_str(), &cc, 2);
                cout<<endl<<"MTU: "<<n;
            }else if((unsigned int)cb==3)
            {
                cout<<" -> Prefix Information.";
                //Length
                cb=s[71];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //Prefix Length
                cb=s[72];
                cout<<endl<<"Prefix Length: "<<(unsigned int)cb;
                cb=s[73];
                bin=chartobin(cb);
                if(bin[0]==1)
                {
                     cout<<endl<<"On-Link Flag: ON";
                }else
                {
                    cout<<endl<<"On-Link Flag: OFF";
                }
                if(bin[1]==1)
                {
                    cout<<endl<<"Autonomous Address Configuration: ON";
                }else
                {
                    cout<<endl<<"Autonomous Address Configuration: OFF";
                }
                //Valid Lifetime
                long long int n;
                stringstream vl;
                cb=s[74];
                bin=chartobin(cb);
                vl<<bin;
                cb=s[75];
                bin=chartobin(cb);
                vl<<bin;
                cb=s[76];
                bin=chartobin(cb);
                vl<<bin;
                cb=s[77];
                bin=chartobin(cb);
                vl<<bin;
                s2=vl.str();
                n=strtoull(s2.c_str(), &cc, 2);
                cout<<endl<<"Valid Lifetime: "<<n;
                //Preferred Lifetime
                stringstream pl;
                cb=s[78];
                bin=chartobin(cb);
                pl<<bin;
                cb=s[79];
                bin=chartobin(cb);
                pl<<bin;
                cb=s[80];
                bin=chartobin(cb);
                pl<<bin;
                cb=s[81];
                bin=chartobin(cb);
                pl<<bin;
                s2=pl.str();
                n=strtoull(s2.c_str(), &cc, 2);
                cout<<endl<<"Preferred Lifetime: "<<n;
                //Prefix
                cout<<endl<<"Prefix: ";
                int cont=0;
                for(int j=86; j<102; j++)
                {
                    cb=s[j];
                    printf("%02x", (unsigned int)cb);
                    cont++;
                    if(j<97)
                    {
                        if(cont==2)
                        {
                        cont=0;
                        cout<<":";
                        }
                    }
                }
            }else
            {
                cout<<endl<<" Tipo No Encontrado.";
            }
        }else if(ident==15)
        {
            //Neighbor Sol.
            //Target Address
            cout<<endl<<"Target Address: ";
            int cont=0;
            for(int j=58; j<74; j++)
            {
                cb=s[j];
                printf("%02x", (unsigned int)cb);
                cont++;
                if(j<73)
                {
                    if(cont==2)
                    {
                    cont=0;
                    cout<<":";
                    }
                }
            }
            //Options
            cb=s[74];
            cout<<endl<<"Type: "<<(unsigned int)cb;
            if((unsigned int)cb==1)
            {
                cout<<" -> 1 = Source link-layer";
                //Length
                cb=s[75];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=76; j<82; j++)
                {
                    cb=s[j];
                    printf("%02x", (unsigned int)cb);
                    if(j<81)
                    {
                        cout<<":";
                    }
                }
            }else
            {
                cout<<endl<<"No encontrado.";
            }
        }else if(ident==16)
        {
            //Neighbor Ad.
            cb=s[58];
            bin=chartobin(cb);
            if(bin[0]==1)
            {
                cout<<endl<<"Router Flag: ON";
            }else
            {
                cout<<endl<<"Router Flag: OFF";
            }
            if(bin[1]==1)
            {
                cout<<endl<<"Solicited Flag: ON";
            }else
            {
                cout<<endl<<"Solicited Flag: OFF";
            }
            if(bin[2]==2)
            {
                cout<<endl<<"Override Flag: ON";
            }else
            {
                cout<<endl<<"Override Flag: OFF";
            }
            //Target Address
            cout<<endl<<"Target Address: ";
            for(int j=62; j<78; j++)
            {
                cb=s[j];
                printf("%02x", (unsigned int)cb);
                if(j<77)
                {
                    cout<<":";
                }
            }
            //Options
            cb=s[78];
            cout<<endl<<"Type: "<<(unsigned int)cb;
            if((unsigned int)cb==2)
            {
                cout<<" -> Target link-layer";
                //Length
                cb=s[79];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=80; j<86; j++)
                {
                    cb=s[j];
                    printf("%02x", (unsigned int)cb);
                    if(j<85)
                    {
                        cout<<":";
                    }
                }
            }else
            {
                cout<<endl<<" Tipo No Encontrado.";
            }
        }else if(ident==17)
        {
            //Redirect
            //Target Address
            cout<<endl<<"Target Address: ";
            for(int j=58; j<74; j++)
            {
                cb=s[j];
                printf("%02x", (unsigned int)cb);
                if(j<73)
                {
                    cout<<":";
                }
            }
            //Destination Address
            cout<<endl<<"Destination Address: ";
            for(int j=74; j<90; j++)
            {
                cb=s[j];
                printf("%02x", (unsigned int)cb);
                if(j<89)
                {
                    cout<<":";
                }
            }
            //Options
            cb=s[90];
            cout<<endl<<"Type: "<<(unsigned int)cb;
            if((unsigned int)cb==2)
            {
                cout<<" -> Target link-layer";
                //Length
                cb=s[91];
                cout<<endl<<"Length: "<<(unsigned int)cb;
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=92; j<108; j++)
                {
                    cb=s[j];
                    printf("%02x", (unsigned int)cb);
                    if(j<107)
                    {
                        cout<<":";
                    }
                }
            }else if((unsigned int)cb==4)
            {
                //Redirect Header
                cout<<" -> Redirect Header";
                //Length
                cb=s[91];
                cout<<endl<<"Length: "<<(unsigned int)cb;
            }else
            {
                cout<<endl<<" Tipo No Encontrado.";
            }
        }else
        {
            cout<<endl<<" Tipo No Encontrado.";
        }
    }
}

#endif // ICMPV6_H_INCLUDED
