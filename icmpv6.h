#ifndef ICMPV6_H_INCLUDED
#define ICMPV6_H_INCLUDED
#include <iostream>
#include "diccionario.h"
using namespace std;

void icmp6 (const struct pcap_pkthdr *header, const u_char *buffer, int payloadLength)
{
    unsigned char currentByte;
    stringstream rawStream;
    string rawData;

    //Converting packet into string
    for(unsigned int j=0; j<header->len; j++)
    {
        rawStream<<buffer[j];
    }
    rawData=rawStream.str();
    
    cout<<endl<<endl<<"                ICMPV6                 "<<endl;
    
    int icmpIdentifier;

    ///----------------TYPE, CODE-----------------------
    currentByte=rawData[54];

    char *bin, *endPtr;
    stringstream typeCodeStream;
    string typeCodeString;

    typeCodeStream<<(unsigned int)currentByte;

    if((unsigned int)currentByte<10)
    {
        currentByte=rawData[55];
        typeCodeStream<<"-"<<(unsigned int)currentByte;
    }
    else{
        typeCodeStream<<"-0";
    }

    typeCodeString=typeCodeStream.str();
    icmpIdentifier=verificarIcmp6(typeCodeString);

    ///---------------Checksum----------------------------
    stringstream checksumStream;

    currentByte=rawData[56];
    checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
    
    currentByte=rawData[57];
    checksumStream<<hex<<setw(2)<<setfill('0')<<(unsigned int)currentByte;
    
    typeCodeString="0x"+checksumStream.str();

    cout<<endl<<"Header Checksum: "<<typeCodeString;

    ///-----------------DATA------------------------------
    if(icmpIdentifier<8)
    {
        //Destination Unreachable Payload
        cout<<endl<<"Payload Lenght: "<<payloadLength-8;
    }
    else if(icmpIdentifier==8||icmpIdentifier==9)
    {
        //Echo Request / Echo Reply
        //Identifier
        long int n;
        stringstream tempStream;

        currentByte=rawData[58];
        bin=chartobin(currentByte);
        tempStream<<bin;

        currentByte=rawData[59];
        bin=chartobin(currentByte);
        tempStream<<bin;

        typeCodeString=tempStream.str();
        n=strtoull(typeCodeString.c_str(), &endPtr, 2);

        cout<<endl<<"Identifier: "<<n;

        //Sequence Number
        stringstream seqStream;

        currentByte=rawData[60];
        bin=chartobin(currentByte);
        seqStream<<bin;

        currentByte=rawData[61];
        bin=chartobin(currentByte);
        seqStream<<bin;

        typeCodeString=seqStream.str();
        n=strtoull(typeCodeString.c_str(), &endPtr, 2);

        cout<<endl<<"Sequence Number: "<<n;
        
        //Payload
        cout<<endl<<"Payload Lenght: "<<payloadLength-12;
    }
    else if(icmpIdentifier>10)
    {
        if(icmpIdentifier==13)
        {
            //Router Solicitation
            //Type
            currentByte=rawData[58];
            cout<<endl<<"Type: "<<(unsigned int)currentByte;

            if((unsigned int)currentByte==1)
            {
                cout<<" -> 1 = Source link-layer";
                
                //Length
                currentByte=rawData[59];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=60; j<66; j++)
                {
                    currentByte=rawData[j];
                    printf("%02x", (unsigned int)currentByte);
                    if(j<65)
                    {
                        cout<<":";
                    }
                }
            }
            else
            {
                cout<<endl<<"No encontrado :v";
            }
        }
        else if(icmpIdentifier==14)
        {
            //Router Advertisement
            //Cur Hop Limit
            currentByte=rawData[58];
            cout<<endl<<"Cur Hop Limit: "<<(unsigned int)currentByte;
            
            //Flags
            currentByte=rawData[59];
            bin=chartobin(currentByte);
            
            if(bin[0]==1)
            {
                cout<<endl<<"Managed Address Flag: ON";
            }
            else
            {
                cout<<endl<<"Managed Address Flag: OFF";
            }
            if(bin[1]==1)
            {
                cout<<endl<<"Other Configuration Flag: ON";
            }
            else
            {
                cout<<endl<<"Other Configuration Flag: OFF";
            }

            //Router Lifetime
            double lifetimeHours;
            long int lifetimeValue;
            stringstream lifetimeStream;

            currentByte=rawData[60];
            bin=chartobin(currentByte);
            lifetimeStream<<bin;

            currentByte=rawData[61];
            bin=chartobin(currentByte);
            lifetimeStream<<bin;

            typeCodeString=lifetimeStream.str();

            lifetimeValue=strtoull(typeCodeString.c_str(), &endPtr, 2);
            lifetimeHours=(lifetimeValue/60)/60;
            
            cout<<endl<<"Router Lifetime: "<<lifetimeValue<<"S. ("<<lifetimeHours<<" H.)";
            
            //Reachable Time
            long long int reachableTime;
            stringstream reachableStream;

            currentByte=rawData[62];
            bin=chartobin(currentByte);
            reachableStream<<bin;

            currentByte=rawData[63];
            bin=chartobin(currentByte);
            reachableStream<<bin;

            currentByte=rawData[64];
            bin=chartobin(currentByte);
            reachableStream<<bin;

            currentByte=rawData[65];
            bin=chartobin(currentByte);
            reachableStream<<bin;

            typeCodeString=reachableStream.str();
            reachableTime=strtoull(typeCodeString.c_str(), &endPtr, 2);
            
            cout<<endl<<"Reachable Time: "<<reachableTime<<" ms.";
            
            //Retrans Timer
            stringstream retransStream;

            currentByte=rawData[66];
            bin=chartobin(currentByte);
            retransStream<<bin;

            currentByte=rawData[67];
            bin=chartobin(currentByte);
            retransStream<<bin;

            currentByte=rawData[68];
            bin=chartobin(currentByte);
            retransStream<<bin;

            currentByte=rawData[69];
            bin=chartobin(currentByte);
            retransStream<<bin;

            typeCodeString=retransStream.str();
            reachableTime=strtoull(typeCodeString.c_str(), &endPtr, 2);
            
            cout<<endl<<"Retrans Time: "<<reachableTime<<" ms.";
            
            //Options
            currentByte=rawData[70];
            cout<<endl<<"Type: "<<(unsigned int)currentByte;
            
            if((unsigned int)currentByte==1)
            {
                //Source Link-Layer
                cout<<" -> Source Link-Layer.";
                
                //Length
                currentByte=rawData[71];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=72; j<78; j++)
                {
                    currentByte=rawData[j];
                    printf("%02x", (unsigned int)currentByte);
                    if(j<77)
                    {
                        cout<<":";
                    }
                }
            }
            else if((unsigned int)currentByte==5)
            {
                //MTU
                cout<<" -> MTU.";
                
                //Length
                currentByte=rawData[71];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //MTU
                long long int mtuValue;
                stringstream mtuStream;

                currentByte=rawData[72];
                bin=chartobin(currentByte);
                mtuStream<<bin;

                currentByte=rawData[73];
                bin=chartobin(currentByte);
                mtuStream<<bin;

                currentByte=rawData[74];
                bin=chartobin(currentByte);
                mtuStream<<bin;

                currentByte=rawData[75];
                bin=chartobin(currentByte);
                mtuStream<<bin;

                typeCodeString=mtuStream.str();
                mtuValue=strtoull(typeCodeString.c_str(), &endPtr, 2);
                
                cout<<endl<<"MTU: "<<mtuValue;
            }
            else if((unsigned int)currentByte==3)
            {
                cout<<" -> Prefix Information.";
                
                //Length
                currentByte=rawData[71];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //Prefix Length
                currentByte=rawData[72];
                cout<<endl<<"Prefix Length: "<<(unsigned int)currentByte;
                
                currentByte=rawData[73];
                bin=chartobin(currentByte);
                
                if(bin[0]==1)
                {
                     cout<<endl<<"On-Link Flag: ON";
                }
                else
                {
                    cout<<endl<<"On-Link Flag: OFF";
                }
                
                if(bin[1]==1)
                {
                    cout<<endl<<"Autonomous Address Configuration: ON";
                }
                else
                {
                    cout<<endl<<"Autonomous Address Configuration: OFF";
                }
                
                //Valid Lifetime
                long long int validLifetime;
                stringstream validStream;

                currentByte=rawData[74];
                bin=chartobin(currentByte);
                validStream<<bin;

                currentByte=rawData[75];
                bin=chartobin(currentByte);
                validStream<<bin;

                currentByte=rawData[76];
                bin=chartobin(currentByte);
                validStream<<bin;

                currentByte=rawData[77];
                bin=chartobin(currentByte);
                validStream<<bin;

                typeCodeString=validStream.str();
                validLifetime=strtoull(typeCodeString.c_str(), &endPtr, 2);
                
                cout<<endl<<"Valid Lifetime: "<<validLifetime;
                
                //Preferred Lifetime
                stringstream preferredStream;

                currentByte=rawData[78];
                bin=chartobin(currentByte);
                preferredStream<<bin;

                currentByte=rawData[79];
                bin=chartobin(currentByte);
                preferredStream<<bin;

                currentByte=rawData[80];
                bin=chartobin(currentByte);
                preferredStream<<bin;

                currentByte=rawData[81];
                bin=chartobin(currentByte);
                preferredStream<<bin;

                typeCodeString=preferredStream.str();
                validLifetime=strtoull(typeCodeString.c_str(), &endPtr, 2);
                
                cout<<endl<<"Preferred Lifetime: "<<validLifetime;
                
                //Prefix
                cout<<endl<<"Prefix: ";
                
                int counter=0;
                
                for(int j=86; j<102; j++)
                {
                    currentByte=rawData[j];
                    
                    printf("%02x", (unsigned int)currentByte);
                    
                    counter++;
                    
                    if(j<97)
                    {
                        if(counter==2)
                        {
                        counter=0;
                        cout<<":";
                        }
                    }
                }
            }
            else
            {
                cout<<endl<<" Tipo No Encontrado.";
            }
        }
        else if(icmpIdentifier==15)
        {
            //Neighbor Sol.
            //Target Address
            cout<<endl<<"Target Address: ";
            
            int counter=0;
            
            for(int j=58; j<74; j++)
            {
                currentByte=rawData[j];
                
                printf("%02x", (unsigned int)currentByte);
                
                counter++;
                
                if(j<73)
                {
                    if(counter==2)
                    {
                    counter=0;
                    cout<<":";
                    }
                }
            }
            
            //Options
            currentByte=rawData[74];

            cout<<endl<<"Type: "<<(unsigned int)currentByte;
            
            if((unsigned int)currentByte==1)
            {
                cout<<" -> 1 = Source link-layer";
                
                //Length
                currentByte=rawData[75];
                
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //Mac Address
                cout<<endl<<"Mac Address: ";
                
                for(int j=76; j<82; j++)
                {
                    currentByte=rawData[j];
                    
                    printf("%02x", (unsigned int)currentByte);
                    
                    if(j<81)
                    {
                        cout<<":";
                    }
                }
            }
            else
            {
                cout<<endl<<"No encontrado.";
            }
        }
        else if(icmpIdentifier==16)
        {
            //Neighbor Ad.
            currentByte=rawData[58];
            
            bin=chartobin(currentByte);
            
            if(bin[0]==1)
            {
                cout<<endl<<"Router Flag: ON";
            }
            else
            {
                cout<<endl<<"Router Flag: OFF";
            }

            if(bin[1]==1)
            {
                cout<<endl<<"Solicited Flag: ON";
            }
            else
            {
                cout<<endl<<"Solicited Flag: OFF";
            }

            if(bin[2]==2)
            {
                cout<<endl<<"Override Flag: ON";
            }
            else
            {
                cout<<endl<<"Override Flag: OFF";
            }

            //Target Address
            cout<<endl<<"Target Address: ";
            
            for(int j=62; j<78; j++)
            {
                currentByte=rawData[j];
                
                printf("%02x", (unsigned int)currentByte);
                
                if(j<77)
                {
                    cout<<":";
                }
            }

            //Options
            currentByte=rawData[78];

            cout<<endl<<"Type: "<<(unsigned int)currentByte;
            
            if((unsigned int)currentByte==2)
            {
                cout<<" -> Target link-layer";
                
                //Length
                currentByte=rawData[79];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //Mac Address
                cout<<endl<<"Mac Address: ";
                for(int j=80; j<86; j++)
                {
                    currentByte=rawData[j];
                    
                    printf("%02x", (unsigned int)currentByte);
                    
                    if(j<85)
                    {
                        cout<<":";
                    }
                }
            }
            else
            {
                cout<<endl<<" Tipo No Encontrado.";
            }
        }
        else if(icmpIdentifier==17)
        {
            //Redirect
            //Target Address
            cout<<endl<<"Target Address: ";
            
            for(int j=58; j<74; j++)
            {
                currentByte=rawData[j];
                
                printf("%02x", (unsigned int)currentByte);
                
                if(j<73)
                {
                    cout<<":";
                }
            }

            //Destination Address
            cout<<endl<<"Destination Address: ";
            
            for(int j=74; j<90; j++)
            {
                currentByte=rawData[j];
                
                printf("%02x", (unsigned int)currentByte);
                
                if(j<89)
                {
                    cout<<":";
                }
            }

            //Options
            currentByte=rawData[90];
            
            cout<<endl<<"Type: "<<(unsigned int)currentByte;
            
            if((unsigned int)currentByte==2)
            {
                cout<<" -> Target link-layer";
                
                //Length
                currentByte=rawData[91];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
                
                //Mac Address
                cout<<endl<<"Mac Address: ";
                
                for(int j=92; j<108; j++)
                {
                    currentByte=rawData[j];
                    
                    printf("%02x", (unsigned int)currentByte);
                    
                    if(j<107)
                    {
                        cout<<":";
                    }
                }
            }
            else if((unsigned int)currentByte==4)
            {
                //Redirect Header
                cout<<" -> Redirect Header";
                
                //Length
                currentByte=rawData[91];
                cout<<endl<<"Length: "<<(unsigned int)currentByte;
            }
            else
            {
                cout<<endl<<" Tipo No Encontrado.";
            }
        }
        else
        {
            cout<<endl<<" Tipo No Encontrado.";
        }
    }
}

#endif // ICMPV6_H_INCLUDED
