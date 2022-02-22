#define VERSION 3.00
#ifndef uint32_t
#define uint32_t unsigned int
#endif

//#define DEBUG

uint endianSwap(uint n) {
	return(as_uint(as_uchar4(n).s3210));
}


unsigned int SWAP (unsigned int val)
{
    return(as_uint(as_uchar4(val).s3210));
}

#define OLD_SHA256

#ifdef OLD_SHA256

#define F1(x,y,z)   (bitselect(z,y,x))
#define F0(x,y,z)   (bitselect (x, y, ((x) ^ (z))))
#define mod(x,y) ((x)-((x)/(y)*(y)))
#define shr32(x,n) ((x) >> (n))
#define rotl32(a,n) rotate ((a), (n))

#define S0(x) (rotl32 ((x), 25u) ^ rotl32 ((x), 14u) ^ shr32 ((x),  3u))
#define S1(x) (rotl32 ((x), 15u) ^ rotl32 ((x), 13u) ^ shr32 ((x), 10u))
#define S2(x) (rotl32 ((x), 30u) ^ rotl32 ((x), 19u) ^ rotl32 ((x), 10u))
#define S3(x) (rotl32 ((x), 26u) ^ rotl32 ((x), 21u) ^ rotl32 ((x),  7u))

#define SHA256C00 0x428a2f98u
#define SHA256C01 0x71374491u
#define SHA256C02 0xb5c0fbcfu
#define SHA256C03 0xe9b5dba5u
#define SHA256C04 0x3956c25bu
#define SHA256C05 0x59f111f1u
#define SHA256C06 0x923f82a4u
#define SHA256C07 0xab1c5ed5u
#define SHA256C08 0xd807aa98u
#define SHA256C09 0x12835b01u
#define SHA256C0a 0x243185beu
#define SHA256C0b 0x550c7dc3u
#define SHA256C0c 0x72be5d74u
#define SHA256C0d 0x80deb1feu
#define SHA256C0e 0x9bdc06a7u
#define SHA256C0f 0xc19bf174u
#define SHA256C10 0xe49b69c1u
#define SHA256C11 0xefbe4786u
#define SHA256C12 0x0fc19dc6u
#define SHA256C13 0x240ca1ccu
#define SHA256C14 0x2de92c6fu
#define SHA256C15 0x4a7484aau
#define SHA256C16 0x5cb0a9dcu
#define SHA256C17 0x76f988dau
#define SHA256C18 0x983e5152u
#define SHA256C19 0xa831c66du
#define SHA256C1a 0xb00327c8u
#define SHA256C1b 0xbf597fc7u
#define SHA256C1c 0xc6e00bf3u
#define SHA256C1d 0xd5a79147u
#define SHA256C1e 0x06ca6351u
#define SHA256C1f 0x14292967u
#define SHA256C20 0x27b70a85u
#define SHA256C21 0x2e1b2138u
#define SHA256C22 0x4d2c6dfcu
#define SHA256C23 0x53380d13u
#define SHA256C24 0x650a7354u
#define SHA256C25 0x766a0abbu
#define SHA256C26 0x81c2c92eu
#define SHA256C27 0x92722c85u
#define SHA256C28 0xa2bfe8a1u
#define SHA256C29 0xa81a664bu
#define SHA256C2a 0xc24b8b70u
#define SHA256C2b 0xc76c51a3u
#define SHA256C2c 0xd192e819u
#define SHA256C2d 0xd6990624u
#define SHA256C2e 0xf40e3585u
#define SHA256C2f 0x106aa070u
#define SHA256C30 0x19a4c116u
#define SHA256C31 0x1e376c08u
#define SHA256C32 0x2748774cu
#define SHA256C33 0x34b0bcb5u
#define SHA256C34 0x391c0cb3u
#define SHA256C35 0x4ed8aa4au
#define SHA256C36 0x5b9cca4fu
#define SHA256C37 0x682e6ff3u
#define SHA256C38 0x748f82eeu
#define SHA256C39 0x78a5636fu
#define SHA256C3a 0x84c87814u
#define SHA256C3b 0x8cc70208u
#define SHA256C3c 0x90befffau
#define SHA256C3d 0xa4506cebu
#define SHA256C3e 0xbef9a3f7u
#define SHA256C3f 0xc67178f2u 

__constant uint k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

#define SHA256_STEP(F0a,F1a,a,b,c,d,e,f,g,h,x,K)        \
{                                                       \
  h += K + x;                                           \
  h += S3 (e) + F1a (e,f,g);                            \
  d += h;                                               \
  h += S2 (a) + F0a (a,b,c);                            \
}                                                       \



#define SHA256_EXPAND(x,y,z,w) (S1 (x) + y + S0 (z) + w) 

static void sha256_process2 (const unsigned int *W, unsigned int *digest)
{
  unsigned int a = digest[0];
  unsigned int b = digest[1];
  unsigned int c = digest[2];
  unsigned int d = digest[3];
  unsigned int e = digest[4];
  unsigned int f = digest[5];
  unsigned int g = digest[6];
  unsigned int h = digest[7];

  unsigned int w0_t = W[0];
  unsigned int w1_t = W[1];
  unsigned int w2_t = W[2];
  unsigned int w3_t = W[3];
  unsigned int w4_t = W[4];
  unsigned int w5_t = W[5];
  unsigned int w6_t = W[6];
  unsigned int w7_t = W[7];
  unsigned int w8_t = W[8];
  unsigned int w9_t = W[9];
  unsigned int wa_t = W[10];
  unsigned int wb_t = W[11];
  unsigned int wc_t = W[12];
  unsigned int wd_t = W[13];
  unsigned int we_t = W[14];
  unsigned int wf_t = W[15];

  #define ROUND_EXPAND(i)                           \
  {                                                 \
    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA256_STEP (F0, F1, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
    SHA256_STEP (F0, F1, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
    SHA256_STEP (F0, F1, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
    SHA256_STEP (F0, F1, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
    SHA256_STEP (F0, F1, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
    SHA256_STEP (F0, F1, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
    SHA256_STEP (F0, F1, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
    SHA256_STEP (F0, F1, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
    SHA256_STEP (F0, F1, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
    SHA256_STEP (F0, F1, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
    SHA256_STEP (F0, F1, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
    SHA256_STEP (F0, F1, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
    SHA256_STEP (F0, F1, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
    SHA256_STEP (F0, F1, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
    SHA256_STEP (F0, F1, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
    SHA256_STEP (F0, F1, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
  }

  ROUND_STEP (0);

  ROUND_EXPAND();
  ROUND_STEP(16);

  ROUND_EXPAND();
  ROUND_STEP(32);

  ROUND_EXPAND();
  ROUND_STEP(48);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}


#define word unsigned int

static void sha256 ( uint pass_len,  const unsigned int *pass,  uint *hash) 
{                 

    int plen=pass_len/4;            
    if (mod(pass_len,4)) plen++;    
    
    unsigned int* p = hash; 
                                    
    unsigned int W[0x10]={0};   
    int loops=plen;             
    int curloop=0;              
    unsigned int State[8]={0};  
    State[0] = 0x6a09e667;      
    State[1] = 0xbb67ae85;      
    State[2] = 0x3c6ef372;      
    State[3] = 0xa54ff53a;      
    State[4] = 0x510e527f;      
    State[5] = 0x9b05688c;      
    State[6] = 0x1f83d9ab;      
    State[7] = 0x5be0cd19;      
                        
    while (loops>0)     
    {                   
        W[0x0]=0x0;     
        W[0x1]=0x0;     
        W[0x2]=0x0;     
        W[0x3]=0x0;     
        W[0x4]=0x0;     
        W[0x5]=0x0;     
        W[0x6]=0x0;     
        W[0x7]=0x0;     
        W[0x8]=0x0;     
        W[0x9]=0x0;     
        W[0xA]=0x0;     
        W[0xB]=0x0;     
        W[0xC]=0x0;     
        W[0xD]=0x0;     
        W[0xE]=0x0;     
        W[0xF]=0x0;     
                        
        for (int m=0;loops!=0 && m<16;m++)      
        {                                       
            W[m]^=SWAP(pass[m+(curloop*16)]);   
            loops--;                            
        }                            
        
                                                        
        if (loops==0 && mod(pass_len,64)!=0)    
        {                                       
            unsigned int padding=0x80<<(((pass_len+4)-((pass_len+4)/4*4))*8);   
            int v=mod(pass_len,64);         
            W[v/4]|=SWAP(padding);          
            if ((pass_len&0x3B)!=0x3B)      
            {                               
                W[0x0F]=pass_len*8;         
            }                               
        }                                   
                                        
        sha256_process2(W,State);       
        curloop++;                      
    }                                   
             

                            
    p[0]=SWAP(State[0]);    
    p[1]=SWAP(State[1]);    
    p[2]=SWAP(State[2]);    
    p[3]=SWAP(State[3]);    
    p[4]=SWAP(State[4]);    
    p[5]=SWAP(State[5]);    
    p[6]=SWAP(State[6]);    
    p[7]=SWAP(State[7]);    
  

    return;                 
}

#else

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

#define ROL32(x, y)		rotate(x, y ## U)
#define SHR(x, y)		(x >> y)
#define SWAP32(a)    	(as_uint(as_uchar4(a).wzyx))

#define S0(x) (ROL32(x, 25) ^ ROL32(x, 14) ^  SHR(x, 3))
#define S1(x) (ROL32(x, 15) ^ ROL32(x, 13) ^  SHR(x, 10))

#define S2(x) (ROL32(x, 30) ^ ROL32(x, 19) ^ ROL32(x, 10))
#define S3(x) (ROL32(x, 26) ^ ROL32(x, 21) ^ ROL32(x, 7))

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + (K + x);      \
    d += temp1; h = temp1 + S2(a) + F0(a,b,c);  \
}

#define F0(y, x, z) bitselect(z, y, z ^ x)
#define F1(x, y, z) bitselect(z, y, x)

#define R0 (W0 = S1(W14) + W9 + S0(W1) + W0)
#define R1 (W1 = S1(W15) + W10 + S0(W2) + W1)
#define R2 (W2 = S1(W0) + W11 + S0(W3) + W2)
#define R3 (W3 = S1(W1) + W12 + S0(W4) + W3)
#define R4 (W4 = S1(W2) + W13 + S0(W5) + W4)
#define R5 (W5 = S1(W3) + W14 + S0(W6) + W5)
#define R6 (W6 = S1(W4) + W15 + S0(W7) + W6)
#define R7 (W7 = S1(W5) + W0 + S0(W8) + W7)
#define R8 (W8 = S1(W6) + W1 + S0(W9) + W8)
#define R9 (W9 = S1(W7) + W2 + S0(W10) + W9)
#define R10 (W10 = S1(W8) + W3 + S0(W11) + W10)
#define R11 (W11 = S1(W9) + W4 + S0(W12) + W11)
#define R12 (W12 = S1(W10) + W5 + S0(W13) + W12)
#define R13 (W13 = S1(W11) + W6 + S0(W14) + W13)
#define R14 (W14 = S1(W12) + W7 + S0(W15) + W14)
#define R15 (W15 = S1(W13) + W8 + S0(W0) + W15)

#define RD14 (S1(W12) + W7 + S0(W15) + W14)
#define RD15 (S1(W13) + W8 + S0(W0) + W15)


void sha256_round(uint *data, uint *buf)
{
	uint temp1;
	uint8 res;
	uint W0 = (data[0]);
	uint W1 = (data[1]);
	uint W2 = (data[2]);
	uint W3 = (data[3]);
	uint W4 = (data[4]);
	uint W5 = (data[5]);
	uint W6 = (data[6]);
	uint W7 = (data[7]);
	uint W8 = (data[8]);
	uint W9 = (data[9]);
	uint W10 = (data[10]);
	uint W11 = (data[11]);
	uint W12 = (data[12]);
	uint W13 = (data[13]);
	uint W14 = (data[14]);
	uint W15 = (data[15]);

	uint v0 = buf[0];
	uint v1 = buf[1];
	uint v2 = buf[2];
	uint v3 = buf[3];
	uint v4 = buf[4];
	uint v5 = buf[5];
	uint v6 = buf[6];
	uint v7 = buf[7];

	P(v0, v1, v2, v3, v4, v5, v6, v7, W0, 0x428A2F98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W1, 0x71374491);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W2, 0xB5C0FBCF);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W3, 0xE9B5DBA5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W4, 0x3956C25B);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W5, 0x59F111F1);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W6, 0x923F82A4);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W7, 0xAB1C5ED5);
	P(v0, v1, v2, v3, v4, v5, v6, v7, W8, 0xD807AA98);
	P(v7, v0, v1, v2, v3, v4, v5, v6, W9, 0x12835B01);
	P(v6, v7, v0, v1, v2, v3, v4, v5, W10, 0x243185BE);
	P(v5, v6, v7, v0, v1, v2, v3, v4, W11, 0x550C7DC3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, W12, 0x72BE5D74);
	P(v3, v4, v5, v6, v7, v0, v1, v2, W13, 0x80DEB1FE);
	P(v2, v3, v4, v5, v6, v7, v0, v1, W14, 0x9BDC06A7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, W15, 0xC19BF174);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0xE49B69C1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0xEFBE4786);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x0FC19DC6);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x240CA1CC);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x2DE92C6F);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4A7484AA);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5CB0A9DC);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x76F988DA);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x983E5152);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA831C66D);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xB00327C8);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xBF597FC7);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xC6E00BF3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD5A79147);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0x06CA6351);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x14292967);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x27B70A85);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x2E1B2138);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x4D2C6DFC);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x53380D13);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x650A7354);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x766A0ABB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x81C2C92E);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x92722C85);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0xA2BFE8A1);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA81A664B);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xC24B8B70);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xC76C51A3);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xD192E819);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD6990624);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R14, 0xF40E3585);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x106AA070);

	P(v0, v1, v2, v3, v4, v5, v6, v7, R0, 0x19A4C116);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R1, 0x1E376C08);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x2748774C);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x34B0BCB5);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x391C0CB3);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4ED8AA4A);
	P(v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5B9CCA4F);
	P(v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x682E6FF3);
	P(v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x748F82EE);
	P(v7, v0, v1, v2, v3, v4, v5, v6, R9, 0x78A5636F);
	P(v6, v7, v0, v1, v2, v3, v4, v5, R10, 0x84C87814);
	P(v5, v6, v7, v0, v1, v2, v3, v4, R11, 0x8CC70208);
	P(v4, v5, v6, v7, v0, v1, v2, v3, R12, 0x90BEFFFA);
	P(v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xA4506CEB);
	P(v2, v3, v4, v5, v6, v7, v0, v1, RD14, 0xBEF9A3F7);
	P(v1, v2, v3, v4, v5, v6, v7, v0, RD15, 0xC67178F2);

	buf[0] = (v0 + buf[0]);
	buf[1] = (v1 + buf[1]);
	buf[2] = (v2 + buf[2]);
	buf[3] = (v3 + buf[3]);
	buf[4] = (v4 + buf[4]);
	buf[5] = (v5 + buf[5]);
	buf[6] = (v6 + buf[6]);
	buf[7] = (v7 + buf[7]);
}


void SHA2_256_80(uint *hdr, uint *digestOut)
{
	uint W[16];
	uint digest[8];

	digest[0] = H0;
	digest[1] = H1;
	digest[2] = H2;
	digest[3] = H3;
	digest[4] = H4;
	digest[5] = H5;
	digest[6] = H6;
	digest[7] = H7;
	
	for(int i = 0; i < 16; ++i) W[i] = SWAP32(hdr[i]);
	
	sha256_round(W, digest);
	
	for(int i = 0; i < 4; ++i) W[i] = SWAP32(hdr[16 + i]);
	
	W[4] = 0x80000000;
	
	for(int i = 5; i < 15; ++i) W[i] = 0x00;
	
	W[15] = 80 * 8;
	sha256_round(W, digest);
	
	for(int i = 0; i < 8; ++i) digestOut[i] = SWAP32(digest[i]);
}

void SHA2_256_32(unsigned char *plain_key,  uint *digestOut) {

	int t, gid, msg_pad;
	int stop, mmod;
	uint i, item, total;
	uint W[80], temp, A,B,C,D,E,F,G,H,T1,T2;
	int current_pad;
	
	msg_pad=0;

	total = 32%64>=56?2:1 + 32/64;

	uint digest[8];

	digest[0] = H0;
	digest[1] = H1;
	digest[2] = H2;
	digest[3] = H3;
	digest[4] = H4;
	digest[5] = H5;
	digest[6] = H6;
	digest[7] = H7;

	A = digest[0];
	B = digest[1];
	C = digest[2];
	D = digest[3];
	E = digest[4];
	F = digest[5];
	G = digest[6];
	H = digest[7];

	//for (t = 0; t < 80; t++){
	//W[t] = 0x00000000;
	//}

	//current_pad = 32;

	//i=current_pad;

	for (t = 0 ; t < 8 ; t++)
		W[t] = endianSwap(((uint *)plain_key)[t]);

	W[8] =  0x80000000;
	for(int i = 9; i < 15; ++i) W[i] = 0x00;
	
	W[15] =  32*8 ;

	sha256_round(W, digest);

	for ( int i = 0; i < 8; i++)
	digestOut[i] = endianSwap(digest[i]);

}

static void sha256 ( uint pass_len,  const unsigned int *pass,  uint *hash) 
{
	if(pass_len == 32) SHA2_256_32(pass, hash);
	else SHA2_256_80(pass, hash);
}

#endif









static inline uint CLZz(uint x)
{
    x |= x >> 1;

    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    x -= (x >> 1) & 0x55555555U;
    x = ((x >> 2) & 0x33333333U) + (x & 0x33333333U);
    x = ((x >> 4) + x) & 0x0f0f0f0fU;
    x += x >> 8;
    x += x >> 16;
    return 32U - (x & 0x0000003fU);
}



#define HASHOP_ADD 0
#define HASHOP_XOR 1
#define HASHOP_SHA_SINGLE 2
#define HASHOP_SHA_LOOP 3
#define HASHOP_MEMGEN 4
#define HASHOP_MEMADD 5
#define HASHOP_MEMXOR 6
#define HASHOP_MEM_SELECT 7
#define HASHOP_END 8
#define HASHOP_READMEM2 9
#define HASHOP_LOOP 10
#define HASHOP_ENDLOOP 11
#define HASHOP_IF 12
#define HASHOP_STORETEMP 13
#define HASHOP_EXECOP 14
#define HASHOP_MEMADDHASHPREV 15
#define HASHOP_MEMXORHASHPREV 16

#define SWAP32(x)	as_uint(as_uchar4(x).s3210)

__kernel void dyn_hash (__global uint* byteCode, __global uint* hashResult, __global uint* hostHeader, __global uint* NonceRetBuf, const ulong target, __global uint* global_memgen) {
    
    int computeUnitID = get_global_id(0) - get_global_offset(0);

    __global uint* hostHashResult = &hashResult[computeUnitID * 8];

    uint myHeader[20];
    uint myHashResult[8];

    uint nonce = get_global_id(0) * GPU_LOOPS;

    for ( int i = 0; i < 19; i++)
        myHeader[i] = hostHeader[i];
	
	myHeader[19] = nonce;
	
    uint bestNonce = nonce;
    uint bestDiff = 0;
    uint bestHash[8];


    uint prevHashSHA[8];
    sha256(32, &myHeader[1], prevHashSHA);

    __global uint* myMemGen = &global_memgen[computeUnitID * 512 * 8];
    uint tempStore[8];
    
    
    uint hashCount = 0;
    while (hashCount < GPU_LOOPS) {

        /*
        if (get_global_id(0) != 0)
            return;

        unsigned char* hh = myHeader;
        for (int i = 0; i < 80; i++)
            printf("%02X", hh[i]);
        printf("\n");
        */

            sha256(80, myHeader, myHashResult);



            uint linePtr = 0;
            uint done = 0;
            uint currentMemSize = 0;
            uint instruction = 0;

            uint loop_opcode_count;
            uint loop_line_ptr;


            while (1) {

                /*
                printf("%08X%08X%08X%08X%08X%08X%08X%08X",
                    myHashResult[0],
                    myHashResult[1],
                    myHashResult[2],
                    myHashResult[3],
                    myHashResult[4],
                    myHashResult[5],
                    myHashResult[6],
                    myHashResult[7]
                    );
                    */

                if (byteCode[linePtr] == HASHOP_ADD) {
                    linePtr++;
                    for (int i = 0; i < 8; i++)
                        myHashResult[i] += byteCode[linePtr + i];
                    linePtr += 8;
                }


                else if (byteCode[linePtr] == HASHOP_XOR) {
                    linePtr++;
                    for (int i = 0; i < 8; i++)
                        myHashResult[i] ^= byteCode[linePtr + i];
                    linePtr += 8;
                }


                else if (byteCode[linePtr] == HASHOP_SHA_SINGLE) {
                    sha256(32, myHashResult, myHashResult);
                    linePtr++;
                }


                else if (byteCode[linePtr] == HASHOP_SHA_LOOP) {
                    linePtr++;
                    uint loopCount = byteCode[linePtr];
                    for (int i = 0; i < loopCount; i++) {
                        sha256(32, myHashResult, myHashResult);
                    }
                    linePtr++;
                }


                else if (byteCode[linePtr] == HASHOP_MEMGEN) {
                    linePtr++;

                    currentMemSize = byteCode[linePtr];

                    for (int i = 0; i < currentMemSize; i++) {
                        sha256(32, myHashResult, myHashResult);
                        for (int j = 0; j < 8; j++)
                            myMemGen[i*8+j] = myHashResult[j];
                    }


                    linePtr++;
                }


                else if (byteCode[linePtr] == HASHOP_MEMADD) {
                    linePtr++;

                    for (int i = 0; i < currentMemSize; i++)
                        for (int j = 0; j < 8; j++)
                            myMemGen[i*8+j] += byteCode[linePtr + j];

                    linePtr += 8;
                }

                else if (byteCode[linePtr] == HASHOP_MEMADDHASHPREV) {
                    linePtr++;

                    for (int i = 0; i < currentMemSize; i++)
                        for (int j = 0; j < 8; j++) {
                            myMemGen[i * 8 + j] += myHashResult[j] + prevHashSHA[j];
                        }

                }


                else if (byteCode[linePtr] == HASHOP_MEMXOR) {
                    linePtr++;

                    for (int i = 0; i < currentMemSize; i++)
                        for (int j = 0; j < 8; j++)
                            myMemGen[i * 8 + j] ^= byteCode[linePtr + j];

                    linePtr += 8;
                }

                else if (byteCode[linePtr] == HASHOP_MEMXORHASHPREV) {
                    linePtr++;

                    for (int i = 0; i < currentMemSize; i++)
                        for (int j = 0; j < 8; j++) {
                            myMemGen[i * 8 + j] += myHashResult[j];
                            myMemGen[i * 8 + j] ^= prevHashSHA[j];
                        }

                }


                else if (byteCode[linePtr] == HASHOP_MEM_SELECT) {
                    linePtr++;
                    uint index = byteCode[linePtr] % currentMemSize;
                    for (int j = 0; j < 8; j++)
                        myHashResult[j] = myMemGen[index*8 + j];

                    linePtr++;
                }

                else if (byteCode[linePtr] == HASHOP_READMEM2) {
                    linePtr++;
                    if (byteCode[linePtr] == 0) {
                        for (int i = 0; i < 8; i++)
                            myHashResult[i] ^= prevHashSHA[i];
                    }
                    else if (byteCode[linePtr] == 1) {
                        for (int i = 0; i < 8; i++)
                            myHashResult[i] += prevHashSHA[i];
                    }

                    linePtr++;  //this is the source, only supports prev hash currently

                    uint index = 0;
                    for (int i = 0; i < 8; i++)
                        index += myHashResult[i];


                    index = index % currentMemSize;

                    for (int j = 0; j < 8; j++)
                        myHashResult[j] = myMemGen[index*8+j];

                    linePtr++;

                }

                else if (byteCode[linePtr] == HASHOP_LOOP) {
                    loop_opcode_count = 0;
                    for (int j = 0; j < 8; j++)
                        loop_opcode_count += myHashResult[j];

                    linePtr++;
                    loop_opcode_count = loop_opcode_count % byteCode[linePtr] + 1;

                    linePtr++;
                    loop_line_ptr = linePtr;        //line to return to after endloop
                }

                else if (byteCode[linePtr] == HASHOP_ENDLOOP) {
                    linePtr++;
                    loop_opcode_count--;
                    if (loop_opcode_count > 0)
                        linePtr = loop_line_ptr;
                }

                else if (byteCode[linePtr] == HASHOP_IF) {
                    linePtr++;
                    uint sum = 0;
                    for (int j = 0; j < 8; j++)
                        sum += myHashResult[j];
                    sum = sum % byteCode[linePtr];
                    linePtr++;
                    uint numToSkip = byteCode[linePtr];
                    linePtr++;
                    if (sum == 0) {
                        linePtr += numToSkip;
                    }
                }

                else if (byteCode[linePtr] == HASHOP_STORETEMP) {
                    for (int j = 0; j < 8; j++)
                        tempStore[j] = myHashResult[j];

                    linePtr++;
                }

                else if (byteCode[linePtr] == HASHOP_EXECOP) {
                    linePtr++;
                    //next byte is source  (hard coded to temp)
                    linePtr++;

                    uint sum = 0;
                    for (int j = 0; j < 8; j++)
                        sum += myHashResult[j];

                    if (sum % 3 == 0) {
                        for (int i = 0; i < 8; i++)
                            myHashResult[i] += tempStore[i];
                    }

                    else if (sum % 3 == 1) {
                        for (int i = 0; i < 8; i++)
                            myHashResult[i] ^= tempStore[i];
                    }

                    else if (sum % 3 == 2) {
                        sha256(32, myHashResult, myHashResult);
                    }

                }

                else if (byteCode[linePtr] == HASHOP_END) {
                    break;
                }

        }
		
        
        ulong res = as_ulong(as_uchar8(((ulong *)myHashResult)[0]).s76543210);
		if(res <= target)
		{
			NonceRetBuf[atomic_inc(NonceRetBuf + 0xFF)] = nonce;
			break;	// we are solo mining, any other solutions will go to waste anyhow
		}
		
        hashCount++;
        nonce++;
        myHeader[19] = nonce;
	}

}
