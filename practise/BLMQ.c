#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
    element_t P, Ppub, Su, V, temp2;
    element_t s, h1, temp1, h,r;
    element_t g,x,T1,T2;
    clock_t start, stop;
    int byte1, byte2;

    //以标准输入的形式，初始化配对类型的变量
    //pbc_demo_pairing_init(pairing, argc, argv);
    //第二个参数是群的阶未r，是40bit的素数，域的阶为q是50bit长的数典型至未160和512
    pbc_param_init_a_gen(par, 40, 50);
    pairing_init_pbc_param(pairing, par);

    //将变量P初始化为群G1中的元素
    element_init_G1(P, pairing);
    //将变量temp1初始化为群G1中的元素
   element_init_G1(Ppub, pairing);
    //将变量temp2初始化为群G2中的元素
    element_init_G1(Su, pairing);
    element_init_G1(V, pairing);
   
    element_init_G1(temp2, pairing);

    //将变量x初始化为群Zr中元素
    element_init_Zr(s, pairing);
    element_init_Zr(r, pairing);
    element_init_Zr(temp1, pairing);
    element_init_Zr(h1, pairing);
    element_init_Zr(h, pairing);

    //将变量y初始化为群GT中的元素
    element_init_GT(g, pairing);
    element_init_GT(x, pairing);
    element_init_GT(T2, pairing);
    element_init_GT(T1, pairing);
    //判断是否是对称配对
    if (!pairing_is_symmetric(pairing))
    {
        fprintf(stderr, "only works with symmetic pairing\n");
        exit(1);
    }
    printf("BLMQ Scheme\n");
    printf("SetUp\n");
    start = clock();
    //随机选择G1中的一个元素赋值给P
    //随机的选择主密钥s
    element_random(s);
    //生成G1的生成元P
    element_random(P);
    //计算Ppub=sP，这是公钥
    element_mul_zn(Ppub, P, s);
    //g = e(p,p)
    pairing_apply(g,P,P,pairing);
    stop = clock();
    printf("the generator of G1 is : \n");
    element_printf("P=%B\n", P);
    element_printf("g=%B\n", g);
    printf("the master key is :\n");
    element_printf("s =%B\n", s);
    printf("the Ppub is :\n");
    element_printf("Ppub =%B\n", Ppub);
    printf("the time of SetUp phase %fs\n", (double)(stop - start));

    printf("Extract\n");
    //签名
    start = clock();
    //模拟H1（IDu）
    element_from_hash(h1, "IDu", 3);
    //temp1 = s+h1 = s+ H1(IDu)
    element_add(temp1,s,h1);
    //temp1 = 1/(s+H1(IDu))
    element_invert(temp1,temp1);
    //Su = temp1 * P = P*（1/（s+H1(IDu)））
    element_mul_zn(Su,P,temp1);

     stop = clock();
    printf("the private key and public key of user is :\n");
    element_printf("Su=  %B\n", Su);
    printf("the time of Extract phase %fs\n", (double)(stop - start));
    
    
    printf("Signing\n");
    start = clock();
    //得到随机数r
    element_random(r);
    //x = g^r
    element_pow_zn(x,g,r);

    //模拟H2（m,x）
    element_from_hash(h,"zfc",3);
    //temp1 = r+h
    element_add(temp1,r,h);
    //V = temp*Su = (r+h)Su
    element_mul_zn(V,Su,temp1);

    stop = clock();
    printf("the signature of message is \n");
    element_printf("h=   %B\n", h);
    element_printf("V=   %B\n", V);
    printf("the time of signing phase %fs\n", (double)(stop - start));

    printf("Verify\n");
    start = clock();
    
    //temp2 = H1(IDu)P
    element_mul_zn(temp2,P,h1);
    //temp2 = temp2+Ppub =  H1(IDu)P+Ppub
    element_add(temp2,temp2,Ppub);

    pairing_apply(T1,V,temp2,pairing);
    //temp1 = -h
    element_neg(temp1,h);
    //T2 = g^-h
    element_pow_zn(T2,g,temp1);
    element_mul(T1,T1,T2);
    if (!element_cmp(x, T1))
    {

        printf("the signature is valid \n");
    }
    else
    {

        printf("the signature is not valid\n");
    }

    stop = clock();
    element_printf("T1 =  %B\n", T1);
    printf("the time of verify phase %fs\n", (double)(stop - start));

    element_clear(P);
 
    element_clear(Ppub);
    element_clear(V);
    element_clear(Su);
    element_clear(temp2);
   
    element_clear(temp1);
    element_clear(s);
    element_clear(h);
    element_clear(r);
    element_clear(h1);
    element_clear(T1);
    element_clear(T2);
    element_clear(g);
     element_clear(x);
    pairing_clear(pairing);

    return 0;
}
