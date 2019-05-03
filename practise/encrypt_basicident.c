#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void print_time(clock_t start,clock_t stop){

    printf("the time of setup phase %fs\n",(double)(stop-start));


}
int main(int argc, char const *argv[])
{
    


    pairing_t pairing;
    element_t s,r;
    element_t P,Ppub,Su,Qu,V;
    element_t T1,T2;
    double t1,t2;
    clock_t start,stop;
    int byte;
    pbc_param_t par;
    //初始化加密类型参数
    pbc_param_init_a_gen(par, 40, 50);
    pairing_init_pbc_param(pairing, par);

    element_init_Zr(s,pairing);
    element_init_Zr(r,pairing);

    //将变量P初始化未G1中的元素
    element_init_G1(P,pairing);
    element_init_G1(Ppub,pairing);
    element_init_G1(Qu,pairing);
    element_init_G1(Su,pairing);
    element_init_G1(V,pairing);

    element_init_GT(T1,pairing);
    element_init_GT(T2,pairing);
    //判断是否是对称配对
    if(!pairing_is_symmetric(pairing)){
        fprintf(stderr,"only works with symmetic pairing\n");
        exit(1);
    }

    printf("BasicIdent Scheme\n");
    printf("system setup\n");
    
    start = clock();
    //生成随机的主密钥
    element_random(s);
    //生成G1的生成元P
    element_random(P);
    //计算Ppub = sP
    element_mul_zn(Ppub,P,s);
    stop = clock();
    element_printf("P=%B\n",P);
    element_printf("s=%B\n",s);
    element_printf("Ppub=%B\n",Ppub);
    //输出系统建立阶段所占用的时间
     printf("the time of setup phase %fs\n",(double)(stop-start));

    printf("Extract \n");
    start = clock();
    //从长度为3的hahs值IDu，确定性的产生用户的公钥U
    element_from_hash(Qu,"IDu",3);
    //计算用户的私钥 Su = s * Qu
    element_mul_zn(Su,Qu,s);
    stop = clock();
    element_printf("Qu = %B\n",Qu);
    element_printf("Su = %B\n",Su);
    //输出密钥提取阶段所话费的时间
    printf("the time of key Extract %fs\n",(double)(stop-start));

    printf("Encrypt\n");
    start = clock();
    //产生随机数r
    element_random(r);
    //计算V=rP
    element_mul_zn(V,P,r);
    //计算T1 = e(Ppub,Qu)
    pairing_apply(T1,Ppub,Qu,pairing);
    //计算T1=T1^r = e(Ppub,Qu)^r
    element_pow_zn(T1,T1,r);
    stop = clock();
    element_printf("r = %B\n",r);
    element_printf("V = %B\n",V);
    element_printf("T1 = %B\n",T1);
    printf("the time of encrypt %fs\n",(double)(stop-start));

    printf("Decrypt\n");
    start = clock();
    //T2 = e(V,Su)
    pairing_apply(T2,V,Su,pairing);
    element_printf("T2 = %B\n",T2);
    stop = clock();
    printf("the time of decrypt %fs\n",(double)(stop-start));


    element_clear(P);
    element_clear(Ppub);
    element_clear(s);
    element_clear(Qu);
    element_clear(Su);
    element_clear(T1);
    element_clear(T2);
    element_clear(r);
    element_clear(V);
    pairing_clear(pairing);

    return 0;
}
