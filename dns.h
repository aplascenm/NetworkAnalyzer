#ifndef DNS_H_INCLUDED
#define DNS_H_INCLUDED
#include <iostream>
#include "diccionario.h"


void flagsdns(char *flag_bits)
{
    string opcode_bits;
    stringstream opcode_stream;
    
    if(flag_bits[0]=='0')
    {
        cout<<endl<<"0... .... .... .... = Query";
    }else
    {
        cout<<endl<<"1... .... .... .... = Response";
    }
    
    for(int i=1; i<5; i++)
    {
        opcode_stream<<flag_bits[i];
    }
    
    opcode_bits=opcode_stream.str();
    
    for(int j=0; j<8; j++)
    {
        if(opcode_bits==flagsdns1[j])
        {
            cout<<endl<<flagsdns1[j+1];
        }
    }

    if(flag_bits[5]=='0')
    {
        cout<<endl<<".... .0.. .... .... = Non-authoritative DNS answer";
    }
    else
    {
        cout<<endl<<".... .1.. .... .... = Authoritative DNS answer";
    }

    if(flag_bits[6]=='0')
    {
        cout<<endl<<".... ..0. .... .... = Message not truncated";
    }
    else
    {
        cout<<endl<<".... ..1. .... .... = Message truncated";
    }

    if(flag_bits[7]=='0')
    {
        cout<<endl<<".... ...0 .... .... = Non-recursive Query";
    }
    else
    {
        cout<<endl<<".... ...1 .... .... = Recursive Query";
    }
}

void flagsdns2(char *flag_bits)
{
    string rcode_bits;
    stringstream rcode_stream;
 
    if(flag_bits[0]=='0')
    {
        cout<<endl<<".... .... 0... .... = Recursion not available";
    }
    else
    {
        cout<<endl<<".... .... 1... .... = Recursive available";
    }

    if(flag_bits[2]=='0')
    {
        cout<<endl<<".... .... .0.. .... = Authority portion was not authenticated by the server";
    }
    else
    {
        cout<<endl<<".... .... .1.. .... = Authority portion was authenticated by the server";
    }

    for(int i=4; i<8; i++)
    {
        rcode_stream<<flag_bits[i];
    }

    rcode_bits=rcode_stream.str();
    
    for(int j=0; j<8; j++)
    {
        if(rcode_bits==flagsdns22[j])
        {
            cout<<endl<<flagsdns22[j+1];
        }
    }
}

void dns(const struct pcap_pkthdr *header, const u_char *buffer, int ip_version, int transport_protocol)
{
    unsigned char current_byte;
    stringstream packet_stream;
    string packet_string;

    for(unsigned int j=0; j<header->len; j++)
    {
            packet_stream<<buffer[j];
    }

    packet_string=packet_stream.str();
    
    ///
    char *bin;

    if(ip_version==4)
    {
        cout<<endl<<endl<<"                DNS - IPV4                 "<<endl;
        
        //Transaction ID
        long int transaction_id;
        stringstream binary_stream;
        string binary_string;
        char *end_ptr;
        
        current_byte=packet_string[42];
        bin=chartobin(current_byte);
        binary_stream<<bin;
        
        current_byte=packet_string[43];
        bin=chartobin(current_byte);
        binary_stream<<bin;
        
        binary_string=binary_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        
        cout<<endl<<"Transaction ID: "<<transaction_id;
        
        //FLAGS
        //1 byte
        current_byte=packet_string[44];
        bin=chartobin(current_byte);
        flagsdns(bin);
        
        //2 Byte
        current_byte=packet_string[45];
        bin=chartobin(current_byte);
        flagsdns2(bin);
        
        //Questions
        stringstream question_stream;
        
        current_byte=packet_string[46];
        bin=chartobin(current_byte);
        question_stream<<bin;

        current_byte=packet_string[47];
        bin=chartobin(current_byte);
        question_stream<<bin;

        binary_string=question_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Questions: "<<transaction_id;

        //Answers
        stringstream answer_stream;
        
        current_byte=packet_string[48];
        bin=chartobin(current_byte);
        answer_stream<<bin;

        current_byte=packet_string[49];
        bin=chartobin(current_byte);
        answer_stream<<bin;

        binary_string=answer_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Answers RRs: "<<transaction_id;
        
        //Authority
        stringstream authority_stream;

        current_byte=packet_string[50];
        bin=chartobin(current_byte);
        authority_stream<<bin;

        current_byte=packet_string[51];
        bin=chartobin(current_byte);
        authority_stream<<bin;

        binary_string=authority_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Authority RRs: "<<transaction_id;
        
        //Additional
        stringstream additional_stream;

        current_byte=packet_string[52];
        bin=chartobin(current_byte);
        additional_stream<<bin;

        current_byte=packet_string[53];
        bin=chartobin(current_byte);
        additional_stream<<bin;

        binary_string=additional_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Additional RRs: "<<transaction_id;

        //Query
    }
    else
    {
        cout<<endl<<endl<<"                DNS - IPV6                 "<<endl;
        
        //Transaction ID
        long int transaction_id;
        stringstream binary_stream;
        string binary_string;
        char *end_ptr;

        current_byte=packet_string[62];
        bin=chartobin(current_byte);
        binary_stream<<bin;

        current_byte=packet_string[63];
        bin=chartobin(current_byte);
        binary_stream<<bin;

        binary_string=binary_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        
        cout<<endl<<"Transaction ID: "<<transaction_id;
        
        //FLAGS
        //1 byte
        current_byte=packet_string[64];
        bin=chartobin(current_byte);
        flagsdns(bin);

        //2 Byte
        current_byte=packet_string[65];
        bin=chartobin(current_byte);
        flagsdns2(bin);

        //Questions
        stringstream question_stream;

        current_byte=packet_string[66];
        bin=chartobin(current_byte);
        question_stream<<bin;

        current_byte=packet_string[67];
        bin=chartobin(current_byte);
        question_stream<<bin;

        binary_string=question_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Questions: "<<transaction_id;

        //Answers
        stringstream answer_stream;

        current_byte=packet_string[68];
        bin=chartobin(current_byte);
        answer_stream<<bin;

        current_byte=packet_string[69];
        bin=chartobin(current_byte);
        answer_stream<<bin;

        binary_string=answer_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Answers RRs: "<<transaction_id;
        
        //Authority
        stringstream authority_stream;

        current_byte=packet_string[70];
        bin=chartobin(current_byte);
        authority_stream<<bin;

        current_byte=packet_string[71];
        bin=chartobin(current_byte);
        authority_stream<<bin;

        binary_string=authority_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Authority RRs: "<<transaction_id;

        //Additional
        stringstream additional_stream;

        current_byte=packet_string[72];
        bin=chartobin(current_byte);
        additional_stream<<bin;

        current_byte=packet_string[73];
        bin=chartobin(current_byte);
        additional_stream<<bin;
        
        binary_string=additional_stream.str();
        transaction_id=strtoull(binary_string.c_str(), &end_ptr, 2);
        cout<<endl<<"Additional RRs: "<<transaction_id;
        //Query
    }
}


#endif // DNS_H_INCLUDED
