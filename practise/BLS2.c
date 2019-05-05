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
void HexStrToByte(const char *source, unsigned char *dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte = toupper(source[i + 1]);

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
    return;
}

int main(int argc, char *argv[])
{

    pairing_t pairing;
    //参数
    pbc_param_t par;
    // initialization

    //生命一系列的变量
    element_t P, Y, M, W;
    element_t x;
    element_t T1, T2;
    clock_t start, stop;
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

    // char *p_str = "4B7FD64E6E5C00";
    // //unsigned char data0[128]={'\0'};
    // int n0 =  element_length_in_bytes_compressed(P);//计算需要多大的值用于保存压缩数据的大小
    // unsigned char *p_data = pbc_malloc(n0);
    // HexStrToByte(p_str,p_data,strlen(p_str));
    // element_from_bytes_compressed(P, p_data);//解压
    // element_printf("p_str decompressed = %B\n", P);
    element_random(P);
    //判断是否是对称配对
    if (!pairing_is_symmetric(pairing))
    {
        fprintf(stderr, "only works with symmetic pairing\n");
        exit(1);
    }
    char *w_str = "76A9085F65E101";
    char *y_str = "0E4C5493620C01";

    //unsigned char data1[128]={'\0'};
    int n = element_length_in_bytes_compressed(W); //计算需要多大的值用于保存压缩数据的大小
    unsigned char *w_data = pbc_malloc(n);
    
    printf("the len of pairing %d\n",n);
    printf("the strlen of w_str %ld\n",strlen(w_str));
    HexStrToByte(w_str, w_data, strlen(w_str));
    printf("the strlen of w_data %ld\n",strlen(w_data));
    printf("coord = ");
    int i = 0;
    for (i = 0; i < n; i++)
    {
        printf("%02X", w_data[i]);
    }
    printf("\n");
    element_from_bytes_compressed(W, w_data); //解压
    element_printf("w_str decompressed = %B\n", W);

    //unsigned char data2[128]={'\0'};
    int n1= element_length_in_bytes_compressed(Y); //计算需要多大的值用于保存压缩数据的大小
    unsigned char *y_data = pbc_malloc(n1);
    printf("the strlen of y_str %ld\n",strlen(y_str));
    HexStrToByte(y_str, y_data, strlen(y_str));
    printf("the strlen of y_data %ld\n",strlen(y_data));
    printf("coord = ");
    for (i = 0; i < n; i++)
    {
        printf("%02X", y_data[i]);
    }
    printf("\n");

    element_from_bytes_compressed(Y, y_data); //解压
    element_printf("y_str decompressed = %B\n", Y);

    element_from_hash(M,"messageofsign",13);
    element_printf("the value of M= %B\n", M);
    pairing_apply(T1, P, W, pairing);
    pairing_apply(T2, Y, M, pairing);
    
    pbc_free(w_data);
    pbc_free(y_data);
    // pbc_free(w_data1);
    // pbc_free(y_data1);
    //pbc_free(p_data);
    if (!element_cmp(T1, T2))
    {

        printf("the signature is valid\n");
    }
    else
    {

        printf("the signature is not  valid\n");
    }

    element_clear(P);
    element_clear(Y);
    element_clear(M);
    element_clear(W);
    element_clear(x);
    element_clear(T1);
    element_clear(T2);
    pairing_clear(pairing);

    return 0;
}
