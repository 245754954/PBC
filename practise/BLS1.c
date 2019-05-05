#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
//字节流转换为十六进制字符串
void ByteToHexStr(const unsigned char *source, char *dest, int sourceLen)

{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i++)
    {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f;

        highByte += 0x30;

        if (highByte > 0x39)
            dest[i * 2] = highByte + 0x07;
        else
            dest[i * 2] = highByte;

        lowByte += 0x30;
        if (lowByte > 0x39)
            dest[i * 2 + 1] = lowByte + 0x07;
        else
            dest[i * 2 + 1] = lowByte;
    }
    return;
}

void Hex2Str(const char *sSrc, char *sDest, int nSrcLen)
{
    int i;
    char szTmp[3];

    for (i = 0; i < nSrcLen; i++)
    {
        sprintf(szTmp, "%02X", (unsigned char)sSrc[i]);
        memcpy(&sDest[i * 2], szTmp, 2);
    }
    return;
}


//十六进制字符串转换为字节流
//同时为了将十六进制字符串回复成字节流
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;
    
    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);


        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;


        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;


        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
}

int main(int argc, char *argv[])
{

    pairing_t pairing;
    //参数
    pbc_param_t par;
    // initialization

    //生命一系列的变量
    element_t P,Y,M,W,Y_temp,W_temp;
    element_t x;
    element_t T1,T2;
    clock_t start,stop;
    int byte;

    //以标准输入的形式，初始化配对类型的变量
    //pbc_demo_pairing_init(pairing, argc, argv);
    //第二个参数是群的阶未r，是40bit的素数，域的阶为q是50bit长的数典型至未160和512
    pbc_param_init_a_gen(par, 40, 50);
    pairing_init_pbc_param(pairing, par);

    //将变量P初始化为群G1中的元素
    element_init_G1(P, pairing);
    //将变量temp1初始化为群G1中的元素
 

    element_init_G1(Y, pairing);
    element_init_G1(Y_temp, pairing);
    element_init_G1(W_temp, pairing);
    //将变量Q初始化为群G2中的元素
    element_init_G1(M, pairing);
    //将变量temp2初始化为群G2中的元素
    element_init_G1(W, pairing);
    //将变量x初始化为群GT中的元素
    element_init_Zr(x, pairing);
    //将变量y初始化为群GT中的元素
    element_init_GT(T1, pairing);
    //将a初始化未环Zr中的元素
    element_init_GT(T2, pairing);
   //判断是否是对称配对
    if(!pairing_is_symmetric(pairing)){
        fprintf(stderr,"only works with symmetic pairing\n");
        exit(1);
    }
    printf("BLS Scheme\n");
    printf("system setup\n");
    start = clock();
    //随机选择G1中的一个元素赋值给P
    element_random(P);
    element_random(x);
    element_mul_zn(Y, P, x);
    stop = clock();
    printf("the time of setup phase %fs\n",(double)(stop-start));
    element_printf("P=%B\n",P);
    element_printf("private key is x=%B\n",x);
    element_printf("public key is y=%B\n",Y);

    //签名
    start = clock();
    element_from_hash(M,"messageofsign",13);
    element_mul_zn(W ,M, x);
    
    stop  = clock();
    printf("the time of signing phase %fs\n",(double)(stop-start));
    element_printf("the value of M %B\n",M);
    element_printf("the value of W %B\n",W);

    printf("Verify\n");
    start = clock();
    pairing_apply(T1,P,W,pairing);

    element_from_hash(M,"messageofhash",13);
    element_printf("the value of M= %B\n",M);
    pairing_apply(T2,Y,M,pairing);

    if(!element_cmp(T1,T2)){

        printf("the signature is valid\n");
    }else{

        printf("the signature is not  valid\n");
    }
    stop  = clock();
    printf("the time of verify phase %fs\n",(double)(stop-start));

    element_printf("origin W= %B\n",W);
    int n = element_length_in_bytes_compressed(W);
    unsigned char *w_data = pbc_malloc(n);
    unsigned char *w_data1 = pbc_malloc(n);
    element_to_bytes_compressed(w_data,W);
    printf("the value of W len %d\n",n);
    // char buf[512]={'\0'};
    // char tmp[3]={'\0'};
    // int i=0;
    // printf("coord = ");
    //将以将为什么需要将字符串专程十六进制字符串，：
    //因为c语言中一个字符占8个bit，0-255之间能表示一些特殊的字符，例如问号
    //为了打印的时候不显示特殊的字符，需要将一个字节拆成高四位和低四位，
    //高四位前面补四位0,低四位前面补四个0,这样一个字符，就变成了两个字符，
    //但是打印出来以后就没有一些特殊的符号了，更有利于人们的观察
    // for (i = 0; i < n; i++) {
    //   sprintf(tmp,"%02X", data[i]);//X 表示以十六进制形式输出 02 表示不足两位,前面补0输出 
    //   strcat(buf,tmp);
    // }
    // printf("the len of strlen(buf) %ld\n",strlen(buf));
    // printf("the value of str %s\n",buf);
    char w_str[128]={'\0'};
    //将字节数组转换成十六进制字数组，注意：十六进制字节数组只是字节数组的一个子集
    //字节数组按%c打印出来，仍然还有许多不好认识的字节，但是转成十六进制字节以后就都是可以认识的
    ByteToHexStr(w_data,w_str,n);
    printf("the value of w_str %s\n",w_str);
    printf("\n");

    //unsigned char data1[128]={'\0'};
    HexStrToByte(w_str,w_data1,strlen(w_str));
    element_from_bytes_compressed(W_temp, w_data1);//解压
    element_printf("w_temp decompressed = %B\n", W_temp);


    element_printf("origin Y= %B\n",Y);
    int n1 = element_length_in_bytes_compressed(Y);
    unsigned char *y_data = pbc_malloc(n1);
    unsigned char *y_data1 = pbc_malloc(n1);
    element_to_bytes_compressed(y_data,Y);
    printf("the value of Y len %d\n",n1);
    

    char y_str[128]={'\0'};
    //将字节数组转换成十六进制字数组，注意：十六进制字节数组只是字节数组的一个子集
    //字节数组按%c打印出来，仍然还有许多不好认识的字节，但是转成十六进制字节以后就都是可以认识的
    ByteToHexStr(y_data,y_str,n1);
    printf("the value of y_str %s\n",y_str);
    printf("\n");

    //unsigned char data2[128]={'\0'};
    HexStrToByte(y_str,y_data1,strlen(y_str));
   
    element_from_bytes_compressed(Y_temp, y_data1);//解压
    element_printf("y_temp decompressed = %B\n", Y_temp);


    element_from_hash(M,"messageofsign",13);

    pairing_apply(T1,P,W_temp,pairing);
    pairing_apply(T2,Y_temp,M,pairing);

    if(!element_cmp(T1,T2)){

        printf("the signature is valid\n");
    }else{

        printf("the signature is not  valid\n");
    }
    



    #if 1
    element_printf("origin P= %B\n",P);
    int n3 = element_length_in_bytes_compressed(P);
    unsigned char *p_data = pbc_malloc(n3);
    element_to_bytes_compressed(p_data,P);
    printf("the value of Y len %d\n",n3);
    

    char p_str[128]={'\0'};
    //将字节数组转换成十六进制字数组，注意：十六进制字节数组只是字节数组的一个子集
    //字节数组按%c打印出来，仍然还有许多不好认识的字节，但是转成十六进制字节以后就都是可以认识的
    ByteToHexStr(p_data,p_str,n);
    printf("the value of p_str %s\n",p_str);
    printf("\n");

    unsigned char data3[128]={'\0'};
    HexStrToByte(p_str,data3,strlen(p_str));
   
    element_from_bytes_compressed(P, data3);//解压
    element_printf("p_str decompressed = %B\n", P);
    #endif 

    pbc_free(w_data);
    pbc_free(y_data);
    
    element_clear(P);
    element_clear(Y_temp);
    element_clear(W_temp);
    element_clear(Y);
    element_clear(M);
    element_clear(W);
    element_clear(x);
    element_clear(T1);
    element_clear(T2);
    pairing_clear(pairing);

    return 0;
}
