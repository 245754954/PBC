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
    element_t P,U,V,W,temp1,temp3;
    element_t x,y,m,r,temp2;
    element_t T1,T2;
    clock_t start,stop;
    int byte1,byte2;

    //以标准输入的形式，初始化配对类型的变量
    //pbc_demo_pairing_init(pairing, argc, argv);
    //第二个参数是群的阶未r，是40bit的素数，域的阶为q是50bit长的数典型至未160和512
    pbc_param_init_a_gen(par, 40, 50);
    pairing_init_pbc_param(pairing, par);

    //将变量P初始化为群G1中的元素
    element_init_G1(P, pairing);
    //将变量temp1初始化为群G1中的元素
    element_init_G1(U, pairing);
    //将变量Q初始化为群G2中的元素
    element_init_G1(V, pairing);
    //将变量temp2初始化为群G2中的元素
    element_init_G1(W, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp3, pairing);

    //将变量x初始化为群Zr中元素
    element_init_Zr(x, pairing);
    element_init_Zr(y, pairing);
    element_init_Zr(m, pairing);
    element_init_Zr(r, pairing);
    element_init_Zr(temp2, pairing);
    //将变量y初始化为群GT中的元素
    element_init_GT(T1, pairing);
    //将a初始化未环Zr中的元素
    element_init_GT(T2, pairing);
   //判断是否是对称配对
    if(!pairing_is_symmetric(pairing)){
        fprintf(stderr,"only works with symmetic pairing\n");
        exit(1);
    }
    printf("BB Scheme\n");
    printf("KeyGen\n");
    start = clock();
    //随机选择G1中的一个元素赋值给P
    //生成签名这的私钥x,y
    element_random(x);
    element_random(y);
    //生成G1的生成元P
    element_random(P);
    //计算U=xP，这是公钥 
    element_mul_zn(U, P, x);
    //计算公钥 V=yP
    element_mul_zn(V, P, y);
    stop = clock();
    printf("the generator of G1 is : \n");
    element_printf("P=%B\n",P);
    printf("the private key is :\n");
    element_printf("x =%B\n",x);
    element_printf("y =%B\n",y);
    printf("the public  key is :\n");
    element_printf("U =%B\n",U);
    element_printf("V =%B\n",V);
    printf("the time of KeyGen phase %fs\n",(double)(stop-start));

    printf("Sign\n");
    //签名
    start = clock();
    //生成要要钱名的消息m
    element_random(m);
    //生成签名这选择的随机数r
    element_random(r);
    //计算temp2 = ry
    element_mul(temp2,y,r);
    //计算temp2 = temp2+m 也就是temp2 = m+ry
    element_add(temp2,temp2,m);
    //计算temp2 = x+m+ry
    element_add(temp2,temp2,x);
    //如果x+m+ry不为0,计算其逆元
    if(!element_is0(temp2)){
        element_invert(temp2,temp2);
        element_mul_zn(W,P,temp2);
    }else{

        printf("choose another random number r!\n");
        exit(1);
    }

    stop  = clock();
    printf("the message is m :\n");
    element_printf("m = %B\n",m);
    printf("the signature of message is \n");
    element_printf("W=  %B\n",W);
    element_printf("r=  %B\n",r);
    printf("the time of signing phase %fs\n",(double)(stop-start));

    printf("Verify\n");
    start = clock();
    //计算temp1 = rV
    element_mul_zn(temp1,V,r);
    //计算temp3 = mP
    element_mul_zn(temp3,P,m);
    //计算temp1 = mP+rV
    element_add(temp1,temp1,temp3);
    //计算temp1 = U+mP+rV
    element_add(temp1,temp1,U);
    //计算T1 = e(U+mP+rV,W)
    pairing_apply(T1,temp1,W,pairing);
    pairing_apply(T2,P,P,pairing);
    if(!element_cmp(T1,T2)){

        printf("the signature is valid\n");
    }else{

        printf("the signature is not  valid\n");
    }
    stop  = clock();
    printf("the time of verify phase %fs\n",(double)(stop-start));


    printf("the signature of message is \n");
    element_printf("e(p,p)=   %B\n",T2);
    element_printf("e(U+mP+rV,W)=   %B\n",T1);

    element_clear(P);
    element_clear(U);
    element_clear(temp1);
    element_clear(V);
    element_clear(W);
    element_clear(temp3);
    element_clear(x);
    element_clear(y);
    element_clear(m);
    element_clear(r);
     element_clear(temp2);
    element_clear(T1);
    element_clear(T2);
    pairing_clear(pairing);

    return 0;
}
