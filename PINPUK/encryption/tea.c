#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// TEA Tiny Encryption Algorithm
//==============================


// vecteurs de test pour TEA
// référence : http://www.cix.co.uk/~klockstone/teavect.htm
//  1  : 41ea3a0a 94baa940
//  2  : 4e8e7829 7d8236d8
//  4  : b84e28af b6b62088
//  8  : 5ddf75d9 7a4ce68f
// 16  : 4ec5d2e2 5ada1d89
// 32  : 7d2c6c57 7a6adb4d
// 64  : 2bb0f1b3 c023ed11
//  1  : 00000000 00000000


// chiffrement
// clair[2] : clair 64 bits
// crypto[2] : cryptogramme calculé 64 bits
// k[4] : clé 128 bits
void tea_chiffre(uint32_t * clair,uint32_t * crypto, uint32_t * k)
{
    uint32_t    y=clair[0],
                z=clair[1],
                sum=0;
    int i;
    for (i=0;i<32;i++)
    {
        sum += 0x9E3779B9L;
        y += ((z << 4)+k[0]) ^ (z+sum) ^ ((z >> 5)+k[1]);
        z += ((y << 4)+k[2]) ^ (y+sum) ^ ((y >> 5)+k[3]);
    }
    crypto[0]=y; crypto[1]=z;
}

// déchiffrement
// crypto[2] : cryptogramme
// clair[2] : clair calculé
// k[4] : clé 128 bits
void tea_dechiffre(uint32_t* crypto ,uint32_t* clair, uint32_t*k)
{
    uint32_t    y=crypto[0],
                z=crypto[1],
                sum=0xC6EF3720L;
    int i;
    for (i=0;i<32;i++)
    {
        z -= ((y << 4)+k[2]) ^ (y+sum) ^ ((y >> 5)+k[3]);
        y -= ((z << 4)+k[0]) ^ (z+sum) ^ ((z >> 5)+k[1]);
        sum -= 0x9E3779B9L;
    }
    clair[0]=y; clair[1]=z;
}

int main()
{
    printf("Hello TEA!\n");

    // programme pour produire les suites de validation
    uint32_t pz[1024]={0,0,0,0,0,0};
    int n;
    for (n=1;n<=64;n++)
    {
        tea_chiffre(pz+n,pz+n,pz+n+2);
        if (n==(n&-n)) // si n est une puissance de 2
        {
            printf("%3d : %08x %08x\n", n, pz[n], pz[n+1]);
        }
        pz[n+6]=pz[n];
    }
    for (n=64; n>0; n--)
    {
        tea_dechiffre(pz+n, pz+n, pz+n+2);
    }
    n=1;
    printf("%3d : %08x %08x\n", n, pz[n], pz[n+1]);

    return 0;
}

