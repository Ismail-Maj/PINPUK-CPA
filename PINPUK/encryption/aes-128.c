#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>


// Programme console de référence AES-128
// n'est testé que pour une taille de bloc et de clé de 128 bits
////////////////////////////////////////

// Interface :
void KeyExpansion(uint8_t*Key);
void aes_encrypt(uint8_t*crypto, uint8_t *plain);
void aes_decrypt(uint8_t*plain, uint8_t *crypto);


/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define NB 4
// The number of 32 bit words in a key.
#define NK 4
// Key length in bytes [128 bit]
#define KEYLEN (NK*4)
// Longueur du block en octets (128 bits)
#define BLOCKLEN (NB*4)
// The number of rounds in AES Cipher.
#define NR 10


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[NB][NB];


// data crypto 128 bits : soit table de 16 octets, soit table de 4 mots 32 bits
union
{
    uint8_t     b[BLOCKLEN];
    state_t     s;
} dcry, cle;


// The array that stores the round keys.
static uint8_t RoundKey[176];


// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256]  =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };




/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/


static uint8_t xtime(uint8_t x)
{
    if ((x&0x80)==0) return x<<1;
    return (x<<1)^0x1b;
}

// This function produces NB(NR+1) round keys. The round keys are used in each round to decrypt the states.
void KeyExpansion(uint8_t*Key)
{
      int i, j, k;
      uint8_t tempa[NB]; // Used for the column/row operations
      uint8_t x;
      uint8_t*p;
      uint8_t*q;
      // The first round key is the key itself.
      for (i=0;i<NK*4;i++)
      {
          RoundKey[i]=Key[i];
      }
      x=1;
      // All other round keys are found from the previous round keys.
      for(i=NK; (i < (NB * (NR + 1))); ++i)
      {
            p=RoundKey+(i-1)*4;
            for(j = 0; j < 4; ++j)
            {
                tempa[j]=RoundKey[(i-1) * 4 + j];
            }
            if (i % NK == 0)
            {
                // This function rotates the 4 bytes in a word to the left once.
                // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

                // Function RotWord()

                k = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = k;


                // SubWord() is a function that takes a four-byte input word and
                // applies the S-box to each of the four bytes to produce an output word.

                // Function Subword()
                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];

            tempa[0]^=x; //getRconValue(i/NK-1); // =  tempa[0] ^ getRconValue(i/NK); // Rcon[i/NK];
            x=xtime(x);
        }
        else if ( (NK > 6) && (i % NK == 4) )
        {
              // Function Subword()
              tempa[0] = sbox[(tempa[0])];
              tempa[1] = sbox[(tempa[1])];
              tempa[2] = sbox[(tempa[2])];
              tempa[3] = sbox[(tempa[3])];
        }
        p+=4;
        q=p-NK*4;
        p[0]=q[0]^tempa[0];
        p[1]=q[1]^tempa[1];
        p[2]=q[2]^tempa[2];
        p[3]=q[3]^tempa[3];

      }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round)
{
    int i;
    uint8_t* p=RoundKey+round*NB*4;
    for (i=0;i<BLOCKLEN;i++)
    {
        dcry.b[i]^=*p++;
    }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(void)
{
    int i;
    for (i=0;i<BLOCKLEN;i++)
    {
        dcry.b[i]=sbox[dcry.b[i]];
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(void)
{
      uint8_t temp;

      // Rotate first row 1 columns to left
      temp         = dcry.s[0][1];
      dcry.s[0][1] = dcry.s[1][1];
      dcry.s[1][1] = dcry.s[2][1];
      dcry.s[2][1] = dcry.s[3][1];
      dcry.s[3][1] = temp;

      // Rotate second row 2 columns to left
      temp         = dcry.s[0][2];
      dcry.s[0][2] = dcry.s[2][2];
      dcry.s[2][2] = temp;

      temp         = dcry.s[1][2];
      dcry.s[1][2] = dcry.s[3][2];
      dcry.s[3][2] = temp;

      // Rotate third row 3 columns to left
      temp         = dcry.s[0][3];
      dcry.s[0][3] = dcry.s[3][3];
      dcry.s[3][3] = dcry.s[2][3];
      dcry.s[2][3] = dcry.s[1][3];
      dcry.s[1][3] = temp;
}


// MixColumns function mixes the columns of the state matrix
static void MixColumns(void)
{
    uint8_t i;
    uint8_t Tmp,Tm,t;
    uint8_t*p;
    for(i = 0; i < 4; ++i)
    {
        p=dcry.s[i];
        t   = p[0];
        Tmp = p[0] ^ p[1] ^ p[2] ^ p[3] ;
        Tm  = p[0] ^ p[1] ; Tm = xtime(Tm);  p[0] ^= Tm ^ Tmp ;
        Tm  = p[1] ^ p[2] ; Tm = xtime(Tm);  p[1] ^= Tm ^ Tmp ;
        Tm  = p[2] ^ p[3] ; Tm = xtime(Tm);  p[2] ^= Tm ^ Tmp ;
        Tm  = p[3] ^ t ;
        Tm = xtime(Tm);     p[3] ^= Tm ^ Tmp ;
    }
}


// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(void)
{
    int i;
    uint8_t a,b,c,d;
    uint8_t ax, bx, cx, dx;
    uint8_t ax2, bx2, cx2, dx2;
    uint8_t ax3, bx3, cx3, dx3;
    uint8_t* p;
    for(i=0;i<4;++i)
    {
        p=dcry.s[i];
        a = p[0]; ax=xtime(a); ax2=xtime(ax); ax3=xtime(ax2);
        b = p[1]; bx=xtime(b); bx2=xtime(bx); bx3=xtime(bx2);
        c = p[2]; cx=xtime(c); cx2=xtime(cx); cx3=xtime(cx2);
        d = p[3]; dx=xtime(d); dx2=xtime(dx); dx3=xtime(dx2);
        p[0]=ax^ax2^ax3^b^bx^bx3^c^cx2^cx3^d^dx3;
        p[1]=a^ax3^bx^bx2^bx3^c^cx^cx3^d^dx2^dx3;
        p[2]=a^ax2^ax3^b^bx3^cx^cx2^cx3^d^dx^dx3;
        p[3]=a^ax^ax3^b^bx2^bx3^c^cx3^dx^dx2^dx3;
    }
}



// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(void)
{
    int i;
    for (i=0;i<16;i++)
    {
        dcry.b[i]=rsbox[dcry.b[i]];
    }
}

static void InvShiftRows(void)
{
      uint8_t temp;

      // Rotate first row 1 columns to right
      temp        =dcry.s[3][1];
      dcry.s[3][1]=dcry.s[2][1];
      dcry.s[2][1]=dcry.s[1][1];
      dcry.s[1][1]=dcry.s[0][1];
      dcry.s[0][1]=temp;

      // Rotate second row 2 columns to right
      temp        =dcry.s[0][2];
      dcry.s[0][2]=dcry.s[2][2];
      dcry.s[2][2]=temp;

      temp        =dcry.s[1][2];
      dcry.s[1][2]=dcry.s[3][2];
      dcry.s[3][2]=temp;

      // Rotate third row 3 columns to right
      temp        =dcry.s[0][3];
      dcry.s[0][3]=dcry.s[1][3];
      dcry.s[1][3]=dcry.s[2][3];
      dcry.s[2][3]=dcry.s[3][3];
      dcry.s[3][3]=temp;
}


// chiffrement de plain vers crypto
// la clé est celle qui a été développée par KeyExpansion(Key)
void aes_encrypt(uint8_t*crypto, uint8_t *plain)
{
    uint8_t round = 0;
    int i;

    for (i=0;i<BLOCKLEN;i++)
    {
        dcry.b[i]=plain[i];
    }

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0);

    // There will be NR rounds.
    // The first NR-1 rounds are identical.
    // These NR-1 rounds are executed in the loop below.
    for(round = 1; round < NR; ++round)
    {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes();
    ShiftRows();
    AddRoundKey(NR);
    for (i=0;i<BLOCKLEN;i++)
    {
        crypto[i]=dcry.b[i];
    }

}


// déchiffrement de crypto vers plain
// la clé est celle qui a été développée par KeyExpansion(Key)
void aes_decrypt(uint8_t*plain, uint8_t *crypto)
{
    uint8_t round=0;
    int i;

    for (i=0;i<BLOCKLEN;i++)
    {
        dcry.b[i]=crypto[i];
    }

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(NR);

    // There will be NR rounds.
    // The first NR-1 rounds are identical.
    // These NR-1 rounds are executed in the loop below.
    for(round=NR-1;round>0;round--)
    {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(round);
        InvMixColumns();
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);
    for (i=0;i<BLOCKLEN;i++)
    {
    plain[i]=dcry.b[i];
    }
}


/***************************************************************************************************/

// conversion d'un caractère hexa en entier
// rend -1 si ce n'est pas un caractère hexa
int hexadigit(char c)
{
    if ((c>='0')&&(c<='9')) return c-'0';
    if ((c>='a')&&(c<='f')) return c-'a'+10;
    if ((c>='A')&&(c<='F')) return c-'A'+10;
    return -1;
}

// conversion d'une chaine hexa s en table d'octets d
// non robuste
void hexastring(uint8_t*d, char*s)
{
    char c=*s++;
    char c1;
    while (c!=0)
    {
        c1=*s++;
        *d++=(hexadigit(c)<<4)+hexadigit(c1);
        c=*s++;
    }
}

// conversion d'une table d'octets s en chaîne de caractère hexa d
void stringhexa(char*d, uint8_t*s)
{
    int i;
    for (i=0;i<16;i++)
    {
        sprintf(d,"%02x",*s++);
        d+=2;
    }
    *d=0;
}

// procédure de test
// scrypto = crypto attendu format string
// splain = clair
// skey = clé
// chiffre, vérifie que le cryptogramme est celui attendu
// déchiffre et vérifie que le clair est retrouvé
int test(char*scrypto, char *splain, char*skey)
{
    uint8_t Key[16];
    uint8_t crypto[16];
    uint8_t plain[16];
    uint8_t msg[16];
    uint8_t c[16];
    int i;

    hexastring(c,scrypto);
    hexastring(Key,skey);
    KeyExpansion(Key);
    hexastring(plain, splain);
    aes_encrypt(crypto,plain);

   for (i=0;i<16;i++)
    {
        if (c[i]!=crypto[i]) return 1;
    }

    aes_decrypt(msg,crypto);
    for (i=0;i<16;i++)
    {
        if (msg[i]!=plain[i]) return 1;
    }
    return 0;
}


int main()
{
    printf("Hello aes!\n");
    int r;

    // quelques tests venant de http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip
    r=test("0336763e966d92595a567cc9ce537f5e", "f34481ec3cc627bacd5dc3fb08f273e6","00000000000000000000000000000000");
    printf("%s ",r==0?"ok":"!!");


    r=test("ff4f8391a6a40ca5b25d23bedd44a597", "96ab5c2ff612d9dfaae8c31f30c42168","00000000000000000000000000000000");
    printf("%s ",r==0?"ok":"!!");

    r=test("a1f6258c877d5fcd8964484538bfc92c", "00000000000000000000000000000000","ffffffffffffffffffffffffffffffff");
    printf("%s ",r==0?"ok":"!!");


    r=test("6d251e6944b051e04eaa6fb4dbf78465", "00000000000000000000000000000000","10a58869d74be5a374cf867cfb473859");
    printf("%s ",r==0?"ok":"!!");

    r=test("08a4e2efec8a8e3312ca7460b9040bbf", "58c8e00b2631686d54eab84b91f0aca1","00000000000000000000000000000000");
    printf("%s ",r==0?"ok":"!!");

    // http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
    r=test("3925841d02dc09fbdc118597196a0b32", "3243f6a8885a308d313198a2e0370734","2b7e151628aed2a6abf7158809cf4f3c");
    printf("%s ",r==0?"ok":"!!");

    r=test("69c4e0d86a7b0430d8cdb78070b4c55a", "00112233445566778899aabbccddeeff","000102030405060708090a0b0c0d0e0f");
    printf("%s ",r==0?"ok":"!!");

    // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors#aes-ecb-128
    r=test("3ad77bb40d7a3660a89ecaf32466ef97", "6bc1bee22e409f96e93d7e117393172a","2b7e151628aed2a6abf7158809cf4f3c");
    printf("%s ",r==0?"ok":"!!");
    r=test("f5d3d58503b9699de785895a96fdbaaf", "ae2d8a571e03ac9c9eb76fac45af8e51","2b7e151628aed2a6abf7158809cf4f3c");
    printf("%s ",r==0?"ok":"!!");
    r=test("43b1cd7f598ece23881b00e3ed030688", "30c81c46a35ce411e5fbc1191a0a52ef","2b7e151628aed2a6abf7158809cf4f3c");
    printf("%s ",r==0?"ok":"!!");
    r=test("7b0c785e27e8ad3f8223207104725dd4", "f69f2445df4f9b17ad2b417be66c3710","2b7e151628aed2a6abf7158809cf4f3c");
    printf("%s ",r==0?"ok":"!!");

    return 0;
}


