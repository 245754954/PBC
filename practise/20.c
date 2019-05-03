#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
int main(int argc, char *argv[])
{

    pairing_t pairing;
    //参数
    pbc_param_t par;
    // initialization

    //生命一系列的变量
    element_t P, Q, a, b, c, x, y, temp1, temp2,temp3;

    //以标准输入的形式，初始化配对类型的变量
    //pbc_demo_pairing_init(pairing, argc, argv);
    //第二个参数是群的阶未r，是40bit的素数，域的阶为q是50bit长的数典型至未160和512
    pbc_param_init_a_gen(par, 40, 50);
    pairing_init_pbc_param(pairing, par);

    //将变量P初始化为群G1中的元素
    element_init_G1(P, pairing);
    //将变量temp1初始化为群G1中的元素
    element_init_G1(temp1, pairing);

    element_init_G1(temp3, pairing);
    //将变量Q初始化为群G2中的元素
    element_init_G2(Q, pairing);
    //将变量temp2初始化为群G2中的元素
    element_init_G2(temp2, pairing);
    //将变量x初始化为群GT中的元素
    element_init_GT(x, pairing);
    //将变量y初始化为群GT中的元素
    element_init_GT(y, pairing);
    //将a初始化未环Zr中的元素
    element_init_Zr(a, pairing);
    //将b初始化未环Zr中的元素
    element_init_Zr(b, pairing);
    //将c初始化未环Zr中的元素
    element_init_Zr(c, pairing);

    //随机选择G1中的一个元素赋值给P
    element_random(P);

    element_random(Q);

    element_random(a);
    element_random(b);
    //设置c=== axb  mod  r
    element_mul(c, b, a);
    //执行算数运算x = e(P,Q)
    pairing_apply(x, P, Q, pairing);
    // e(P,Q)^ab
    element_pow_zn(x, x, c);
    //temp1 = aP
    element_pow_zn(temp1, P, a);
    //temp2 = bQ
    element_pow_zn(temp2, Q, b);

    //y = e(aP,bQ)
    pairing_apply(y, temp1, temp2, pairing);

    if (!element_cmp(x, y))
    {

        printf("x is equal to y\n");
    }
    else
    {
        printf("x is not equal to y\n");
    }

    //判断若pairing中的群G1=G2，那么输出1代表zheishiyige对称配对群
    if (pairing_is_symmetric(pairing))
    {

        printf("this is sysmmetic pairing\n");
    }
    else
    {

        printf("this is not sysmmetic pairing\n");
    }

    //输出G1中一个元素的字节数
    int len = pairing_length_in_bytes_G1(pairing);
    printf("the pairing_length_in_bytes_G1 is %d\n ",len);



    //输出G1中一个元素的x坐标的字节数
    int len_x = pairing_length_in_bytes_x_only_G1(pairing);
    printf("the pairing_length_in_bytes_x_G1 is %d\n ",len_x);

    //输出G1中一个元素的压缩格式的字节数
    int len_x_com = pairing_length_in_bytes_compressed_G1(pairing);
    printf("the pairing_length_in_bytes_compressed_G1 is %d\n ",len_x_com);



      //输出G2中一个元素的字节数
    int len2 = pairing_length_in_bytes_G2(pairing);
    printf("the pairing_length_in_bytes_G2 is %d\n ",len);



    //输出G2中一个元素的x坐标的字节数
    int len2_x = pairing_length_in_bytes_x_only_G2(pairing);
    printf("the pairing_length_in_bytes_x_G2 is %d\n ",len_x);



    //输出G2中一个元素的压缩格式的字节数
    int len_x2_com = pairing_length_in_bytes_compressed_G2(pairing);
    printf("the pairing_length_in_bytes_compressed_G2 is %d\n ",len_x2_com);

    //获取GT中一个元素的字节数
    int Gt_len = pairing_length_in_bytes_GT(pairing);
    printf("the pairing_length_in_bytes_GT %d\n",Gt_len);

     //获取Zr中一个元素的字节数
    int Zr_len = pairing_length_in_bytes_Zr(pairing);
    printf("the pairing_length_in_bytes_Zr %d\n",Zr_len);





  
    //n=a+b
    unsigned char data[512];
    char dest[512];
    int com_len = element_to_bytes_compressed(data,P);
    element_printf("the value of P is %B\n",P);
  
    //printf("the strlen of data %d  and data is %s\n",com_len,data);
    int  i=0;
    for(i=0;i<65;i++){
        printf("%c  ",data[i]);
    }
    element_from_bytes_compressed(temp3,data);
    element_printf("the value of temp3 is %B\n",temp3);
    
    element_clear(P);
    element_clear(Q);
    element_clear(a);
    element_clear(b);
    element_clear(c);
    element_clear(x);
    element_clear(y);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    pairing_clear(pairing);

    return 0;
}
