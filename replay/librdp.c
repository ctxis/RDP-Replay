/**
 * Copyright 2014 Context Information Security
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define __rdp_private__
#include "librdp.h"
#include "ssl_decrypt.h"
#include "buffer.h"

/* MSDN has great documentation on message syntax:
 *  http://msdn.microsoft.com/en-us/library/cc240468.aspx
 */

#include <stdio.h>      // printf, sscanf, perror
#include <stdlib.h>     // exit
#include <stdint.h>     // uint16_t, uint32_t
#include <string.h>     // strlen
#include <poll.h>       // poll
#include <unistd.h>     // optarg
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/bn.h>
#include <pthread.h>

static int getBlen(void *, const uint8_t *p, size_t len) ;
static int msg_len(void *, const uint8_t *p, size_t len) ;
static void old_response(void *, const u_char *p, size_t len) ;
static void old_request(void *, const u_char *p, size_t len) ;
static void librdp_init() ;

// SSL support
//  One global keyring for all SSL keys
static void *ssl_kr = 0 ;

// Flags - FIXME: These should be part of ctx!
int do_graph   = 1 ; // FIXME: Used externally
int trace_ord  = 0 ;
int warning    = 0 ;
int do_pointer = 1 ; // FIXME: Used externally
int was_order  = 0 ;
int debug_comp = 0 ;

void *librdp_new()
{
    static int need_init = 1 ;
    ctx_rdp *ctx ;
#define ctx_try(A,B) do { if (0 == (ctx->A=B)) { librdp_del(ctx) ; return 0 ; }} while (0)

    if (need_init)
    {
        librdp_init() ;
        need_init = 0 ;
    }

    ctx = (ctx_rdp *)malloc(sizeof(ctx_rdp)) ;
    if (ctx)
    {
        memset(ctx, 0, sizeof(ctx_rdp)) ;
        ctx_try(req_buf1, buffer_new(getBlen)) ;
        ctx_try(req_buf2, buffer_new(msg_len)) ;
        ctx_try(res_buf1, buffer_new(getBlen)) ;
        ctx_try(res_buf2, buffer_new(msg_len)) ;
        ctx_try(ssl_h,   ssl_proc_create(old_request, old_response, ssl_kr)) ;
        ssl_set_user(ctx->ssl_h, ctx) ;
        buffer_set_user(ctx->req_buf1, ctx) ;
        buffer_set_user(ctx->req_buf2, ctx) ;
        buffer_set_user(ctx->res_buf1, ctx) ;
        buffer_set_user(ctx->res_buf2, ctx) ;
    }
    return ctx ;
}


void librdp_show_keys(void *vp)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    ++SHOW_KEYS(ctx) ;
}

void librdp_save_clipboard(void *vp)
{
    ctx_rdp *ctx   = (ctx_rdp *)vp ;
    CLIP2DISK(ctx) = 1 ;
}

void  librdp_clipboard_16le(void *vp)
{
    ctx_rdp *ctx  = (ctx_rdp *)vp ;
    CLIP16LE(ctx) = 1 ;
}

void librdp_debug_channels(void *vp)
{
    ctx_rdp *ctx  = (ctx_rdp *)vp ;
    DBG_CHAN(ctx) = 1 ;
}

void librdp_debug_capabilities(void *vp)
{
    ctx_rdp *ctx  = (ctx_rdp *)vp ;
    DBG_CAPS(ctx) = 1 ;
}

void librdp_debug_crypt(void *vp)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    DBG_DEC(ctx) = 1 ;
}

void librdp_debug_raw(void *vp)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    DBG_RAW(ctx) = 1 ;
}

void  librdp_show_cursor(void *vp, int yn)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    do_pointer   = yn ;
}

void librdp_sw_gdi(void *vp)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    SW_GDI(ctx)  = 1 ;
}

void  librdp_sound(void *vp)
{
    ctx_rdp *ctx  = (ctx_rdp *)vp ;
    DO_SOUND(ctx) = 1 ;
}

void  librdp_rdpdr(void *vp)
{
    ctx_rdp *ctx  = (ctx_rdp *)vp ;
    DO_RDPDR(ctx) = 1 ;
}

const struct timeval *play_timeval = 0 ;
void librdp_set_ts(void *vp, const struct timeval *tv)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    play_timeval = tv ;
}

void librdp_del(void *vp)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    if (ctx)
    {
        if (ctx->req_buf1)       buffer_del(ctx->req_buf1) ;
        if (ctx->res_buf1)       buffer_del(ctx->res_buf1) ;
        if (ctx->req_buf2)       buffer_del(ctx->req_buf2) ;
        if (ctx->res_buf2)       buffer_del(ctx->res_buf2) ;
        if (ctx->ssl_h)          ssl_proc_free(ctx->ssl_h) ;
        if (ctx->chan_data.buff) free(ctx->chan_data.buff) ;
        free(ctx) ;
    }
}

const char *play_out_file = 0 ;
void librdp_output(void *vp, const char *fname)
{
    ctx_rdp *ctx = (ctx_rdp *)vp ;
    play_out_file = fname ;
}


int play_paused = 0 ;

//------------ Crypt Private File Processing
typedef struct priv_key
{
    struct priv_key *next ;
    char            *name ;
    uint8_t         *public ;
    int              pub_len ;
    BIGNUM           priv ;
    BIGNUM           mod ;
} priv_key ;

static BN_CTX *bn_ctx = 0 ;    // Global for BigNum processing
static priv_key *keys = 0 ;    // Global: We apply keys to *all* contexts

priv_key *new_priv_key()
{
    priv_key *k ;

    // Context for BigNum processing
    if (!bn_ctx) bn_ctx = BN_CTX_new() ;

    k = malloc(sizeof(priv_key)) ;
    if (k)
    {
        k->next    = 0 ;
        k->name    = 0 ;
        k->public  = 0 ;
        k->pub_len = 0 ;
        BN_init(&k->priv) ;
        BN_init(&k->mod) ;
    }
    return k ;
}


void del_priv_key(priv_key *k)
{
    if (k->public) free(k->public) ;
    if (k->name) free(k->name) ;
    BN_free(&k->priv) ;
    BN_free(&k->mod) ;
    free(k) ;
}


static inline void reverse_buf(uint8_t *p, int len)
{
    int i, j ;
    uint8_t temp ;
    for (i = 0, j = len - 1; i < j; i++, j--)
    {
        temp = p[i] ;
        p[i] = p[j] ;
        p[j] = temp ;
    }
}


static uint8_t *read_hex(const char *p, const char *max, uint8_t *out)
{
    int tmp ;
    for ( ; (p+1)<max ; p+=2)
    {
        if (1 != sscanf(p,"%02x", &tmp)) return 0 ;
        *out++ = tmp ;
    }
    return out ;
}


void se_out(const char *msg,
         const u_char *p,
         const u_char *max)
{
    const char *eol = "\n" ;
    printf("%s", msg) ;
    for ( ; p<max ; ++p)
        printf("%02x", (int)*p) ;
    printf("%s",eol) ;
    fflush(stdout) ;
}


// Load a short (380 byte) binary key
static void binkey_380(uint8_t *b, const char *name)
{
    int len = 380-272 ;
    char tmp[len] ;
    priv_key *k ;
    uint8_t hed[] = {
        'R', 'S', 'A', '2',
        0x48,0,0,0,
        0,2,0,0,
        63,0,0,0,
        1,0,1,0
    } ;
    if (memcmp(b,hed,20)) return ;
    k = new_priv_key() ;
    if (!k) return ;
    k->pub_len = 0x5c ;
    k->name    = strdup(name) ;
    k->public  = malloc(k->pub_len) ;
    if ( !(k->name) ||
         !(k->public) ||
         (k->pub_len < 40) )
    {
        del_priv_key(k) ;
        return ;
    }
    memcpy(k->public, b, k->pub_len) ;
    k->public[3] = '1' ; // "RSA1" for public key
    memcpy(tmp,b+272,len) ;
    reverse_buf(tmp, len) ;
    BN_bin2bn(tmp, len, &k->priv) ;
    len = k->pub_len-20 ;
    memcpy(tmp, k->public+20, len) ;
    reverse_buf(tmp, len) ;
    BN_bin2bn(tmp, len, &k->mod) ;
    k->next = keys ;
    keys    = k ;
    printf("Processed private key from %s\n", name) ;
}


// Load a long (1340 byte) binary key
static void binkey_1340(const uint8_t *b, const char *name)
{
    int len = 1340-944 ;
    char tmp[len] ;
    priv_key *k ;
    uint8_t hed[] = {
        'R', 'S', 'A', '2',
        8,1,0,0,
        0,8,0,0,
        255,0,0,0,
        1,0,1,0
    } ;
    if (memcmp(b,hed,20)) return ;
    k = new_priv_key() ;
    if (!k) return ;
    k->pub_len = 0x11c ;
    k->name    = strdup(name) ;
    k->public  = malloc(k->pub_len) ;
    if ( !(k->name) ||
         !(k->public) ||
         (k->pub_len < 40) )
    {
        del_priv_key(k) ;
        return ;
    }
    memcpy(k->public, b, k->pub_len) ;
    k->public[3] = '1' ; // "RSA1" for public key
    memcpy(tmp,b+944,len) ;
    reverse_buf(tmp, len) ;
    BN_bin2bn(tmp, len, &k->priv) ;
    len = k->pub_len-20 ;
    memcpy(tmp, k->public+20, len) ;
    reverse_buf(tmp, len) ;
    BN_bin2bn(tmp, len, &k->mod) ;
    k->next = keys ;
    keys    = k ;
    printf("Processed private key from %s\n", name) ;
}


// Load a key from a binary file
void librdp_key_raw(const char *fname)
{
    int fd, red ;
    uint8_t buff[1350] ;
    const char *name = fname ;
    for (fd=0 ; fname[fd] ; ++fd)
        if ('/'==fname[fd])
            name = fname+fd+1 ;
    fd = open(fname,O_RDONLY) ;
    if (!fd) return ;
    red = read(fd,buff,1350) ;
    if       (380==red) binkey_380(buff,name) ;
    else if (1340==red) binkey_1340(buff,name) ;
    close(fd) ;
}


// Load private keys from file
void librdp_keys(const char *fname)
{
    char buffer[4096] ;
    uint8_t conv[1024] ;
    int count = 0 ;
    int len ;
    int tmp ;
    char *c1, *c2 ;
    FILE *f ;
    priv_key *k ;

    f = fopen(fname, "r") ;
    if (!f) return ;

    while (fgets(buffer,4094,f))
    {
        len = strlen(buffer) ;
        if (len>0 && '\n'==buffer[len-1]) --len ;
        if (len>0 && '\r'==buffer[len-1]) --len ;
        buffer[len] = '\0' ;
        if ( ('\0' == buffer[0]) ||
             ('#'  == buffer[0]) ) continue ;
        c1 = strchr(buffer, ',') ;
        if (!c1) continue ;
        c2 = strchr(c1+1, ',') ;
        if (!c2) continue ;
        if ( (c2-c1-1) & 1) continue ; // Odd charcount in pub!
        if ( (buffer+len-c2-1) & 1) continue ; // Odd charcount in priv!
        k = new_priv_key() ;
        if (!k) return ;
        k->pub_len = (c2-c1) / 2 ;
        k->name    = strndup(buffer,c1-buffer) ;
        k->public  = malloc(k->pub_len) ;
        if ( !(k->name) ||
             !(k->public) ||
             (k->pub_len < 40) ||
             0 == read_hex(c1+1,c2,k->public) ||
             0 == read_hex(c2+1,buffer+len,conv) )
        {
            del_priv_key(k) ;
            break ;
        }
        len = (buffer+len-c2)/2 ;
        reverse_buf(conv, len) ;
        BN_bin2bn(conv, len, &k->priv) ;
        len = k->pub_len-20 ;
        memcpy(conv, k->public+20, len) ;
        reverse_buf(conv, len) ;
        BN_bin2bn(conv, len, &k->mod) ;
        k->next = keys ;
        keys    = k ;
        ++count ;
    }

    printf("Processed %d private keys\n", count) ;
    fclose(f) ;
}


static void *thred(void *varg)
{
    void play_do_Xevents() ;
    pthread_detach(pthread_self()) ;
    for(;;)
    {
       (void)poll(0, 0, 100) ;
        play_do_Xevents() ;
    }
}


// ASN.1 support
#define ASN1_BOOL     (0x01)
#define ASN1_OCT_STR  (0x04)
#define ASN1_SEQ      (0x30)
#define GET_LEN(A) \
    do { \
        if (p >= max) return ; \
        if (p[0]&0x80) { \
            int n=0, m=(*p++)&0x7f ; \
            for( ; m ; --m) \
                n = n<<8 | (*p++) ; \
            A = n ; \
        } else \
            A = (*p++) ; \
    } while (0)
#define EXPECT(V) \
    do {\
        if (p >= max) return ; \
        if ((*p++) != V) return ; \
    } while (0)
#define SKIP_TLV(TAG) \
    do {\
        int l ;\
        EXPECT(TAG) ; \
        GET_LEN(l) ; \
        p += l ; \
        if (p >= max) return ; \
    } while (0)

#define GET2_LE(p) ((p)[0]|(p)[1]<<8)
#define GET4_LE(p) ((p)[0]|(p)[1]<<8|(p)[2]<<16|(p)[3]<<24)


// Parse the Connection Request message (Cli -> Serv)
static void do_con_init(ctx_rdp *ctx, const u_char *p, const u_char *max)
{
    int len ;

    SKIP_TLV(ASN1_OCT_STR) ; // CallingDomainSelector
    SKIP_TLV(ASN1_OCT_STR) ; // CalledDomainSelector
    SKIP_TLV(ASN1_BOOL) ;    // Upwardflag
    SKIP_TLV(ASN1_SEQ) ;     // targetParameters
    SKIP_TLV(ASN1_SEQ) ;     // minimumParameters
    SKIP_TLV(ASN1_SEQ) ;     // maximumParameters
    EXPECT(ASN1_OCT_STR) ;
    GET_LEN(len) ;
    if ((p+len) > max) return ;
    max = p+len ;

    // Now in Generic Conference Control - T.124 in PER! (yuk!)
    // Starts with it's ID:
    // 00 05 00 14 7c 00 01 = oid: 0.0.20.124.0.1 (Generic Conference Control)
    EXPECT(0x00) ; // bit-0 => OctetString, 7 bits pad(0)
    EXPECT(0x05) ; // OctetString length = 5
    EXPECT(0x00) ; // 0.0   \     Octet String
    EXPECT(0x14) ; // 20     \   0.0.20.124.0.1
    EXPECT(0x7c) ; // 124     >- (Generic Conference
    EXPECT(0x00) ; // 0      /     Control)
    EXPECT(0x01) ; // 1     /

    if ((p+2) >= max) return ;
    if ((p[0]&0xc0)!=0x80) return ; // Expect 2-byte length (14-bit)
    len = 0x3fff & (p[0]<<8 | p[1]) ;
    p  += 2 ;
    if ((p+len) > max) return ;
    max = p+len ;

    // Horrible to parse - so we just look for the OID before the userdata
    if ((p+100) >= max) return ;
    for (len=0 ; len<16 ; ++len)
        if ( 0x44==p[len+0] &&
             0x75==p[len+1] &&
             0x63==p[len+2] &&
             0x61==p[len+3] )
            break ;
    if (len==16) return ;
    p += len+4 ;

    if ((p+2) >= max) return ;
    if ((p[0]&0xc0)!=0x80) return ; // Expect 2-byte length (14-bit)
    len = 0x3fff & (p[0]<<8 | p[1]) ;
    p  += 2 ;
    if ((p+len) > max) return ;
    max = p+len ;

    while (p<max)
    {
        int ind, len ;

        // We should be at the start of the data structures
        if ((p+5) >= max) return ;
        ind = p[0] | p[1]<<8 ; // Type Indicator
        len = p[2] | p[3]<<8 ; // Length
        if (len < 5 || (p+len) > max) return ;

    //  printf("Client structure, type %x\n", ind) ;
        switch (ind)
        {
        case 0xc001:
            if (210 <= len)
            {
                void set_pars(int,int,int) ;
                int width  = p[ 8] | p[ 9]<<8 ;
                int height = p[10] | p[11]<<8 ;
                int coldep = p[12] | p[13]<<8 ;
                int bpp ;
                if      (0xca01 == coldep) bpp= 8 ;
                else if (0xca02 == coldep) bpp=15 ;
                else if (0xca03 == coldep) bpp=16 ;
                else if (0xca04 == coldep) bpp=24 ;
                else return ;
                printf("%dx%dx%d\n",width,height,bpp) ;
                set_pars(bpp,width,height) ;
            }
            break ;
        case 0xc003:
            if (len > 20)
            {
                int off = 8 ;
                int ii, jj, count ;
                count = p[4] | p[5]<<8 | p[6]<<16 | p[7]<<24 ;
                if (len < (8+count*12)) break ;
                for (ii=0 ; ii<count ; ++ii)
                {
                    if ( (off+12)>len) break ;
                    if (ii<NUM_CHANS) memcpy(ctx->Channels[ii].name, p+off, 12) ;
                    off += 12 ;
                }
            }
            break ;
        }
        p += len ;
    }
}


// Parse the Connection Response message (Serv -> Cli)
static void do_con_resp(ctx_rdp *ctx, const u_char *p, const u_char *max)
{
    int len ;

    SKIP_TLV(0x0a) ;     // result
    SKIP_TLV(0x02) ;     // calledConnectId
    SKIP_TLV(ASN1_SEQ) ; // domainParameters
    EXPECT(ASN1_OCT_STR) ;
    GET_LEN(len) ;
    if ((p+len) > max) return ;
    max = p+len ;

    // Now in Generic Conference Control - T.124 in PER! (yuk!)
    // Starts with it's ID:
    // 00 05 00 14 7c 00 01 = oid: 0.0.20.124.0.1 (Generic Conference Control)
    EXPECT(0x00) ; // bit-0 => OctetString, 7 bits pad(0)
    EXPECT(0x05) ; // OctetString length = 5
    EXPECT(0x00) ; // 0.0   \     Octet String
    EXPECT(0x14) ; // 20     \   0.0.20.124.0.1
    EXPECT(0x7c) ; // 124     >- (Generic Conference
    EXPECT(0x00) ; // 0      /     Control)
    EXPECT(0x01) ; // 1     /

    // Horrible to parse - so we just look for the OID before the userdata
    if ((p+20) >= max) return ;
    for (len=0 ; len<16 ; ++len)
        if ( 0x4d==p[len+0] && //McDn
             0x63==p[len+1] &&
             0x44==p[len+2] &&
             0x6e==p[len+3] )
            break ;
    if (len==16) return ;
    p += len+4 ;

    if ((p+2) >= max) return ;
    if ((p[0]&0xc0)==0x80) // 2-byte length (14-bit)
    {
        len = 0x3fff & (p[0]<<8 | p[1]) ;
        p  += 2 ;
    }
    else if ((p[0]&0xc0)==0x00) // 1-byte length (6-bit)
        len = *p++ ;
    else
        return ;
    if ((p+len) > max) return ;
    max = p+len ;

    while (p<max)
    {
        int ind, len ;

        // We should be at the start of the data structures
        if ((p+5) >= max) return ;
        ind = p[0] | p[1]<<8 ; // Type Indicator
        len = p[2] | p[3]<<8 ; // Length
        if (len < 5 || (p+len) > max) return ;

   //   printf("Server structure, type %x, len=%d\n", ind, len) ;
        switch (ind)
        {
        case 0x0c02: // Server Security data
            if (len<30) break ;
            {
                // Block is as follows:
                //   02 0c         Type (little endian)
                //   xx xx         Block length (little endian)
                //   xx 00 00 00   Encryption Method
                //   02 00 00 00   Encryption Level (2:ClientCompatible)
                //   20 00 00 00   Rand Length = 32
                //   xx xx xx xx   Cert Length
                // Followed by RAND then CERT
                // CERT: Contains public key
                //   01 00 00 00   dwVersion
                //   01 00 00 00   dwSigAlgId
                //   01 00 00 00   dwKeyAlgId
                //   06 00         wPublicKeyBlobType is 6
                //   xx xx         wPublicKeyBlobLen
            //  int play_response_init(uint8_t *cli, uint8_t *ser, uint32_t enc_type) ;
                int rv ;
                int len_rand = GET4_LE(p+12) ;
                int len_cert = GET4_LE(p+16) ;
                if (len != (20+len_rand+len_cert)) break ;
                if (SEC_RANDOM_SIZE != len_rand) break ;
                memcpy(ctx->server_random, p+20, len_rand) ;
                if (1 == GET4_LE(p+20+len_rand+0) &&
                    1 == GET4_LE(p+20+len_rand+4) &&
                    1 == GET4_LE(p+20+len_rand+8) &&
                    6 == GET2_LE(p+20+len_rand+12) )
                {
                    int pub_len = GET2_LE(p+20+len_rand+14) ;
                    priv_key *prv ;
                    for (prv = keys ; prv ; prv=prv->next)
                        if (prv->pub_len == pub_len && 0==memcmp(prv->public, p+20+len_rand+16, pub_len) )
                        {
                            ctx->active_priv = prv ;
                            printf("We have the private key for this server: %s\n", prv->name) ;
                            break ;
                        }
                    if (!ctx->active_priv)
                    {
                        int ii ;
                        printf("No private key found to match the public key.\n") ;
                        printf("Public Key: ") ;
                        for (ii=0 ; ii<pub_len ; ++ii) printf("%02x",p[20+len_rand+16+ii]) ;
                        printf("\n") ;
                        exit(0) ;
                    }
                }
                ctx->use_enc_type = GET4_LE(p+4) ;
            }
            break ;
        case 0x0c03: // Server Network Data
            if (len>8)
            {
                int c,ii ;
                c = GET2_LE(p+6) ;
                if (len < (8+c*2)) break ;
                for (ii=0 ; ii<c ; ++ii)
                    if (ii<NUM_CHANS)
                        ctx->Channels[ii].num = GET2_LE(p+8+2*ii) ;
            }
            break ;
        }
        p += len ;
    }

    for (len=0 ; len<NUM_CHANS ; ++len)
        if (ctx->Channels[len].num)
        {
            if (0 == memcmp(ctx->Channels[len].name,"cliprdr",8))
                ctx->clip_ch = ctx->Channels[len].num ;
            else if (0 == memcmp(ctx->Channels[len].name,"rdpdr",6))
                ctx->rdpdr_ch = ctx->Channels[len].num ;
            else if (0 == memcmp(ctx->Channels[len].name,"rdpsnd",7))
                ctx->rdpsnd_ch = ctx->Channels[len].num ;
            if (DBG_CHAN(ctx))
                printf(" Chan: %d -> %s\n", (int)ctx->Channels[len].num, ctx->Channels[len].name) ;
        }
}


// Unix command showkey is good for seeing key codes!!
static void KeyEvent(ctx_rdp *ctx, int code, int flags)
{
    // FIXME: Better keycode/keyboard mapping support!!
    // FIXME: Pick up Scroll-lock Num-Lock (and their changes!), +keypad
    // FIXME: Support Windows keys. Not sure that 125,126 are correct.
    // FIXME: This code is nasty! Fix it!!!

    static const char *names[] = {
        "","Escape",                                    //   0-  1
        "1","2","3","4","5","6","7","8","9","0",        //   2- 11
        "-","=","BackSpace","Tab",                      //  12- 15
        "Q","W","E","R","T","Y","U","I","O","P",        //  16- 25
        "[","]","Return","L-Ctrl",                      //  26- 29
        "A","S","D","F","G","H","J","K","L",            //  30- 38
        ";","SingleQuote","BackQuote","L-Shift",        //  39- 42
        "#","Z","X","C","V","B","N","M",                //  43- 50
        ",",".","/",                                    //  51- 53
        "R-Shift","KP_*","L-Alt","Space","CapsLock",    //  54- 58
        "F1","F2","F3","F4","F5",                       //  59- 63
        "F6","F7","F8","F9","F10",                      //  64- 68
        "NumLock","ScrollLock",                         //  69- 70
        "KP_7","KP_8","KP_9","KP_MINUS",                //  71- 74
        "KP_4","KP_5","KP_6","KP_PLUS",                 //  75- 78
        "KP_1","KP_2","KP_3","KP_0","KP_Del",           //  79- 83
        "Unknown","Unknown",                            //  84- 85
        "BackSlash","F11", "F12",                       //  86- 88
        "unknown","unknown","unknown","unknown",        //  89- 92
        "unknown","unknown","unknown","KP_Enter",       //  93- 96
        "R-Ctrl","KP_/","SysRq","AltGr",                //  97-100
        "unknown","Home","Up-Arrow","Page-Up",          // 101-104
        "Left-Arrow","Right-Arrow","End","Down-Arrow",  // 105-108
        "Page-Down","Insert","Delete","unknown"         // 109-112
        "unknown","unknown","unknown","unknown",        // 113-116
        "unknown","unknown","Break","unknown",          // 117-120
        "unknown","unknown","unknown","unknown",        // 121-124
        "L-Windows","R-Windows","Application","unknown",// 125-128
    } ;

    static const char map[2][104] = {

        0,                             //   0
        6,                             //   1          Escape
        '1','2','3','4','5','6','7',   //   2 -   8
        '8','9','0','-','=',           //   9 -  13
        2,                             //  14          BackSpace
        6,                             //  15          Tab
        'q','w','e','r','t','y',       //  16 -  21
        'u','i','o','p','[',']','\n',  //  22 -  28
        5,                             //  29          L-Ctrl
        'a','s','d','f','g','h','j',   //  30 -  36
        'k','l',';','\'','`',          //  37 -  41
        1,                             //  42          L-Shift
        '#','z','x','c','v','b','n',   //  43 -  49
        'm',',','.','/',               //  50 -  53
        1,                             //  54          R-Shift
        0,                             //  55          KP_*
        0,                             //  56          L-Alt
        ' ',                           //  57
        3,                             //  58          Caps
        6,6,6,6,6,6,6,6,6,6,           //  59 -  68    F1 ... F10
        0,                             //  69          NumLock
        0,                             //  70          ScrollLock
        0,                             //  71
        0, 0, 0, 0, 0, 0, 0   , 0,     // 72 - 79
        0, 0, 0, 0, 0, 0, '\\', 6,     // 80 - 87   87=F11
        6, 0, 0, 0, 0, 0, 0   , 0,     // 88 - 95   88=F12
        0, 0, 0, 0, 0, 0, 0   , 0,     // 96 -103

        // Shifted...
        0   , 6   , '!' , '"' , 4   , '$' , '%' , '^' , //  0 -  7      4=£, but is multi-char :(
        '&' , '*' , '(' , ')' , '_' , '+' , 2   , 6   , //  8 - 15
        'Q' , 'W' , 'E' , 'R' , 'T' , 'Y' , 'U' , 'I' , // 16 - 23
        'O' , 'P' , '{' , '}' , '\n', 5   , 'A' , 'S' , // 24 - 31
        'D' , 'F' , 'G' , 'H' , 'J' , 'K' , 'L' , ':' , // 32 - 39
        '@' , '~' , 1   , '|' , 'Z' , 'X' , 'C' , 'V' , // 40 - 47   42=L-Shift
        'B' , 'N' , 'M' , '<' , '>' , '?' , 1   , 0   , // 48 - 55   54=R-Shift
        0   , ' ' , 3   , 6   , 6   , 6   , 6   , 6   , // 56 - 63
        6   , 6   , 6   , 6   , 6   , 0   , 0   , 0   , // 64 - 71
        0   , 0   , 0   , 0   , 0   , 0   , 0   , 0   , // 72 - 79
        0   , 0   , 0   , 0   , 0   , 0   , '|' , 6   , // 80 - 87
        6   , 0   , 0   , 0   , 0   , 0   , 0   , 0   , // 88 - 95
        0   , 0   , 0   , 0   , 0   , 0   , 0   , 0   , // 96 -103
    } ;

    if (!SHOW_KEYS(ctx)) return ;

    if (1 < SHOW_KEYS(ctx))
    {
        printf("Code: %3d  Flags: 0x%04x", code, flags) ;
        if (flags&0x0100) printf(" Extended") ;
        if      (0xc000 == (flags&0xc000)) printf(" Key-UP  ") ;
        else if (0x0000 == (flags&0xc000)) printf(" Key-DOWN") ;
        else                               printf(" Key-??  ") ;
        if (flags & 0x3eff)                printf(" ??      ") ;
        if (code<128)  printf("\t%s", names[code]) ;
        printf("\n") ;
        return ;
    }

    // Flag: KBDFLAGS_EXTENDED      0x0100
    // Flag: KBDFLAGS_DOWN          0x4000
    // Flag: KBDFLAGS_RELEASE       0x8000
    if (0==(flags&0xc000)) // 0=> KeyDown - not already pressed
    {
        //printf("KeyPress at t=%d code=%d\n", tim, code) ;
        int shift = ctx->keybd.pressed[42] | ctx->keybd.pressed[54] ;
        int ctrl  = ctx->keybd.pressed[29] | ctx->keybd.pressed[97] ;
   //   int win   = ctx->keybd.pressed[125] |ctx->keybd.pressed[126] ;
        if (flags&0x0100) // EXTENDED
        {
            printf("<%s%s",
                   ctrl  ? "Ctrl-"  : "",
                   shift ? "Shift-" : "") ;
            if (code<128)
                printf("%s>", names[code]) ;
            else
                printf("Code:%d>", code) ;
        }
        else if (code<104)
        {
            char c = map[shift][code] ;
            ctx->keybd.pressed[code] = 1 ;
            if (ctx->keybd.caps && ( (c>='A' && c<='Z' ) ||
                                     (c>='a' && c<='z' ) ) )
                c ^= 0x20 ;
            switch(c)
            {
            case 0:
                printf("<Code:%d>", code) ;
                break ;
            case 1: // Was Shift - no longer used
                break ;
            case 2:
                printf("<BS>") ; // Backspace
                break ;
            case 3:
                ctx->keybd.caps = 1 - ctx->keybd.caps ;
             // if (ctx->keybd.caps) printf("<CAPS-ON>") ;
             // else                 printf("<CAPS-OFF>") ;
                break ;
            case 4: // Apparently £ is not one character??!? ASCII agrees. :(
                printf("£") ;
            case 5: // Was Ctrl - no longer used
                break ;
            case 6: // Special
                printf("<%s%s%s>",
                       ctrl  ? "Ctrl-"  : "",
                       shift ? "Shift-" : "",
                       names[code]) ;
                break ;
            default:
                if (ctrl)
                    printf("<Ctrl-%s%s>", shift?"Shift-":"", names[code]) ;
                else
                    putchar(c) ;
                break ;
            }
        }
        fflush(stdout) ;
    }
    if (flags==0xc000 && code<104)
    {
        ctx->keybd.pressed[code] = 0 ;
    }
}


static void MouseEvent(ctx_rdp *ctx, int x, int y, int flags)
{
#define PTRFLAGS_WHEEL          0x0200 // The event is a mouse wheel rotation. The only valid flags in a wheel rotation event are PTRFLAGS_WHEEL_NEGATIVE and the WheelRotationMask; all other pointer flags are ignored.
#define PTRFLAGS_WHEEL_NEGATIVE 0x0100 // The wheel rotation value (contained in the WheelRotationMask bit field) is negative and MUST be sign-extended before injection at the server.
#define WheelRotationMask       0x01FF // The bit field describing the number of rotation units the mouse wheel was rotated. The value is negative if the PTRFLAGS_WHEEL_NEGATIVE flag is set.
#define PTRFLAGS_MOVE           0x0800 // Indicates that the mouse position MUST be updated to the location specified by the xPos and yPos fields.
#define PTRFLAGS_DOWN           0x8000 // Indicates that a click event has occurred at the position specified by the xPos and yPos fields. The button flags indicate which button has been clicked and at least one of these flags MUST be set.
#define PTRFLAGS_BUTTON1        0x1000 // Mouse button 1 (left button) was clicked or released. If the PTRFLAGS_DOWN flag is set, then the button was clicked, otherwise it was released.
#define PTRFLAGS_BUTTON2        0x2000 // Mouse button 2 (right button) was clicked or released. If the PTRFLAGS_DOWN flag is set, then the button was clicked, otherwise it was released.
#define PTRFLAGS_BUTTON3        0x4000 // Mouse button 3 (middle button or wheel) was clicked or released. If the PTRFLAGS_DOWN flag is set, then the button was clicked, otherwise it was released.
    void play_cursor(int,int) ;
    if (do_pointer && (flags&PTRFLAGS_MOVE))
    {
        // Only care about mouse movement. Maybe we should show mouse button presses?
        play_cursor(x,y) ;
    }
}


static void parse_capability(ctx_rdp *ctx, u_char *p, u_char *max)
{
/* Capabilities TLV, Type(2),Len(2),V(Len-4)  (Len includes 4-byte TLV header!) */
#define CAPSTYPE_GENERAL			0x0001 // General Capability Set (section 2.2.7.1.1 )
#define CAPSTYPE_BITMAP				0x0002 // Bitmap Capability Set (section 2.2.7.1.2 )
#define CAPSTYPE_ORDER				0x0003 // Order Capability Set (section 2.2.7.1.3 )
#define CAPSTYPE_BITMAPCACHE			0x0004 // Revision 1 Bitmap Cache Capability Set (section 2.2.7.1.4.1 )
#define CAPSTYPE_CONTROL			0x0005 // Control Capability Set (section 2.2.7.2.2 )
#define CAPSTYPE_ACTIVATION			0x0007 // Window Activation Capability Set (section 2.2.7.2.3 )
#define CAPSTYPE_POINTER			0x0008 // Pointer Capability Set (section 2.2.7.1.5 )
#define CAPSTYPE_SHARE				0x0009 // Share Capability Set (section 2.2.7.2.4 )
#define CAPSTYPE_COLORCACHE			0x000A // Color Table Cache Capability Set (see [MS-RDPEGDI] section 2.2.1.1)
#define CAPSTYPE_SOUND				0x000C // Sound Capability Set (section 2.2.7.1.11 )
#define CAPSTYPE_INPUT				0x000D // Input Capability Set (section 2.2.7.1.6 )
#define CAPSTYPE_FONT				0x000E // Font Capability Set (section 2.2.7.2.5 )
#define CAPSTYPE_BRUSH				0x000F // Brush Capability Set (section 2.2.7.1.7 )
#define CAPSTYPE_GLYPHCACHE			0x0010 // Glyph Cache Capability Set (section 2.2.7.1.8 )
#define CAPSTYPE_OFFSCREENCACHE			0x0011 // Offscreen Bitmap Cache Capability Set (section 2.2.7.1.9 )
#define CAPSTYPE_BITMAPCACHE_HOSTSUPPORT	0x0012 // Bitmap Cache Host Support Capability Set (section 2.2.7.2.1 )
#define CAPSTYPE_BITMAPCACHE_REV2		0x0013 // Revision 2 Bitmap Cache Capability Set (section 2.2.7.1.4.2 )
#define CAPSTYPE_VIRTUALCHANNEL			0x0014 // Virtual Channel Capability Set (section 2.2.7.1.10 )
#define CAPSTYPE_DRAWNINEGRIDCACHE		0x0015 // DrawNineGrid Cache Capability Set ([MS-RDPEGDI] section 2.2.1.2)
#define CAPSTYPE_DRAWGDIPLUS			0x0016 // Draw GDI+ Cache Capability Set ([MS-RDPEGDI] section 2.2.1.3)
#define CAPSTYPE_RAIL				0x0017 // Remote Programs Capability Set ([MS-RDPERP] section 2.2.1.1.1)
#define CAPSTYPE_WINDOW				0x0018 // Window List Capability Set ([MS-RDPERP] section 2.2.1.1.2)
#define CAPSETTYPE_COMPDESK			0x0019 // Desktop Composition Extension Capability Set (section 2.2.7.2.8 )
#define CAPSETTYPE_MULTIFRAGMENTUPDATE		0x001A // Multifragment Update Capability Set (section 2.2.7.2.6 )
#define CAPSETTYPE_LARGE_POINTER		0x001B // Large Pointer Capability Set (section 2.2.7.2.7 )
#define CAPSETTYPE_SURFACE_COMMANDS		0x001C // Surface Commands Capability Set (section 2.2.7.2.9 )
#define CAPSETTYPE_BITMAP_CODECS		0x001D // Bitmap Codecs Capability Set (section 2.2.7.2.10 )
#define CAPSSETTYPE_FRAME_ACKNOWLEDGE		0x001E // Frame Acknowledge Capability Set ([MS-RDPRFX] section 2.2.1.3)

    int len1, len2, num ;

    // 2.2.1.13.2.1 Confirm Active PDU Data (TS_CONFIRM_ACTIVE_PDU)
    //  shareId(4)
    //  originatorId(2)
    //  lengthSourceDescriptor(2)
    //  lengthCombinedCapabilities(2)
    //  sourceDescriptor(variable)
    //  numberCapabilities(2)
    //  pad2Octets(2)
    //  capabilitySets(variable)
    //    Contains..
    //    2.2.1.13.1.1.1 Capability Set

    if ( (max-p) < 40) return ;
    len1 = GET2_LE(p+6) ; // lengthSourceDescriptor
    len2 = GET2_LE(p+8) ; // lengthCombinedCapabilities
    p   += 10+len1 ;
    if ( ((p+len2) != max) ||
         (len2<20) )
        return ;

    num = GET2_LE(p) ; // numberCapabilities
    p += 4 ;
    for ( ; num ; --num)
    {
        int type ;
        if ( (max-p) < 5) return ;
        type = GET2_LE(p) ;
        len1 = GET2_LE(p+2) ;
        if ( (len1<4) || ((max-p) < len1) ) return ;
        if (DBG_CAPS(ctx)) se_out("Capability: ", p, p+len1) ;
        switch (type)
        {
        case CAPSTYPE_GLYPHCACHE:
            // We need to set the V2 glyph-cache flag from the CAPSTYPE_GLYPHCACHE
            if (52==len1)
            {
                void play_set_glyph_v2(int val) ;
                int gcc = GET2_LE(p+48) ;
                play_set_glyph_v2(3==gcc) ;
            }
            break ;
        case CAPSTYPE_BITMAP:
            if (28==len1)
            {
                void set_pars(int,int,int) ;
                set_pars(GET2_LE(p+4),GET2_LE(p+12),GET2_LE(p+14)) ;
            }
            break ;
        case CAPSTYPE_BITMAPCACHE_REV2:
            if (40==len1)
            {
                uint16_t flags = p[4] | p[5]<<8 ;
                uint8_t   ents = p[7] ;
                uint8_t     ii ;
                if (warning && (flags&1)) printf("WARNING: PERSISTENT_KEYS_EXPECTED_FLAG set in revision 2 BITMAP capabilities\n") ;
                if (5 < ents)
                    break ; // Bad entry count
                if (DBG_CAPS(ctx))
                    for (ii=0 ; ii<ents ; ++ii)
                        printf(" BitMap Cache-%d: %d entries%s\n", (int)ii, 0x7fffffff&GET4_LE(p+8+ii*4), 0x80&p[11+ii*4] ? " (Persistent)" : "") ;
            }
            break ;
        case CAPSTYPE_DRAWNINEGRIDCACHE:
            if ((12==len1) && DBG_CAPS(ctx))
            {
                uint32_t level = GET4_LE(p+4) ;  // 0,1 or 2 = rev supported
                uint16_t size  = GET2_LE(p+8) ;  // in Kbytes?
                uint16_t ents  = GET2_LE(p+10) ; // Cache entries
                printf("NineGridCache v%d, %dK cache size, %d entries\n", (int)level, (int)size, (int)ents) ;
            }
            break ;
        }
        p += len1 ;
    }
}


static void do_request_pdu_data(ctx_rdp *ctx, u_char *p, u_char *max)
{
    int uc_len ;

    /* Data PDU - 2.2.8.1.1.1.2 Share Data Header
     *  share-ID(4)
     *  pad(1)
     *  stream-id(1)
     *  uncompressedLen(2)
     *  pduType2(1)
     *  compressedType(1)
     *  compressedLen(2)
     */
    if ((max-p)<12)
    {
        printf("BAD: channel 1003: not enough data!\n") ;
        return ;
    }
    uc_len = GET2_LE(p+6) ;
    if (p[9]) // Compression control
    {
        // FIXME: Should these go into history?
        //  Don't think we ever see this??
//      int play_request_decompress(uint8_t *p, uint8_t *max, int flags) ;
//      play_request_decompress(p+12, max, (int)p[9]) ;
//      printf("<<<<<<<<<<<<<<<<<< type=0x%02x len=%d\n", (int)p[9], (int)(max-p-12)) ;
    }
#define PDUTYPE2_UPDATE                      (0x02) /* Graphics Update PDU (section 2.2.9.1.1.3 ) */
#define PDUTYPE2_CONTROL                     (0x14) /* Control PDU (section 2.2.1.15.1 ) */
#define PDUTYPE2_POINTER                     (0x1B) /* Pointer Update PDU (section 2.2.9.1.1.4 ) */
#define PDUTYPE2_INPUT                       (0x1C) /* Input Event PDU (section 2.2.8.1.1.3 ) */
#define PDUTYPE2_SYNCHRONIZE                 (0x1F) /* Synchronize PDU (section 2.2.1.14.1 ) */
#define PDUTYPE2_REFRESH_RECT                (0x21) /* Refresh Rect PDU (section 2.2.11.2.1 ) */
#define PDUTYPE2_PLAY_SOUND                  (0x22) /* Play Sound PDU (section 2.2.9.1.1.5.1 ) */
#define PDUTYPE2_SUPPRESS_OUTPUT             (0x23) /* Suppress Output PDU (section 2.2.11.3.1 ) */
#define PDUTYPE2_SHUTDOWN_REQUEST            (0x24) /* Shutdown Request PDU (section 2.2.2.1.1 ) */
#define PDUTYPE2_SHUTDOWN_DENIED             (0x25) /* Shutdown Request Denied PDU (section 2.2.2.2.1 ) */
#define PDUTYPE2_SAVE_SESSION_INFO           (0x26) /* Save Session Info PDU (section 2.2.10.1.1 ) */
#define PDUTYPE2_FONTLIST                    (0x27) /* Font List PDU (section 2.2.1.18.1 ) */
#define PDUTYPE2_FONTMAP                     (0x28) /* Font Map PDU (section 2.2.1.22.1 ) */
#define PDUTYPE2_SET_KEYBOARD_INDICATORS     (0x29) /* Set Keyboard Indicators PDU (section 2.2.8.2.1.1 ) */
#define PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST (0x2B) /* Persistent Key List PDU (section 2.2.1.17.1 ) */
#define PDUTYPE2_BITMAPCACHE_ERROR_PDU       (0x2C) /* Bitmap Cache Error PDU (see [MS-RDPEGDI] section 2.2.2.3.1) */
#define PDUTYPE2_SET_KEYBOARD_IME_STATUS     (0x2D) /* Set Keyboard IME Status PDU (section 2.2.8.2.2.1 ) */
#define PDUTYPE2_OFFSCRCACHE_ERROR_PDU       (0x2E) /* Offscreen Bitmap Cache Error PDU (see [MS-RDPEGDI] section 2.2.2.3.2) */
#define PDUTYPE2_SET_ERROR_INFO_PDU          (0x2F) /* Set Error Info PDU (section 2.2.5.1.1 ) */
#define PDUTYPE2_DRAWNINEGRID_ERROR_PDU      (0x30) /* DrawNineGrid Cache Error PDU (see [MS-RDPEGDI] section 2.2.2.3.3) */
#define PDUTYPE2_DRAWGDIPLUS_ERROR_PDU       (0x31) /* GDI+ Error PDU (see [MS-RDPEGDI] section 2.2.2.3.4) */
#define PDUTYPE2_ARC_STATUS_PDU              (0x32) /* Auto-Reconnect Status PDU (section 2.2.4.1.1 ) */
#define PDUTYPE2_STATUS_INFO_PDU             (0x36) /* Status Info PDU (section 2.2.5.2 ) */
#define PDUTYPE2_MONITOR_LAYOUT_PDU          (0x37) /* Monitor Layout PDU (section 2.2.12.1 ) */
    if (PDUTYPE2_INPUT==p[8]) // section 2.2.8.1.1.3
    {
        p += 12 ;
        if ((max-p)> 4)
        {
            int num = p[0] | p[1]<<8 ; // Followed by 2-bytes of pad
            p += 4 ;
            for ( ; num ; --num)
            {
                // 4-byte time, 2-byte type, data...
                if ( (max-p) < 6) return ;
                int tim = p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24 ;
                int typ = p[4] | p[5]<<8 ;
                int tmp1, tmp2 ;
                switch(typ)
                {
#define INPUT_EVENT_SYNC     (0x0000) // Indicates a Synchronize Event (section 2.2.8.1.1.3.1.1.5).
#define INPUT_EVENT_MOUSE    (0x8001) // Indicates a Mouse Event (section 2.2.8.1.1.3.1.1.3).
#define INPUT_EVENT_UNUSED   (0x0002) // Indicates an Unused Event (section 2.2.8.1.1.3.1.1.6).
#define INPUT_EVENT_MOUSEX   (0x8002) // Indicates an Extended Mouse Event (section 2.2.8.1.1.3.1.1.4).
#define INPUT_EVENT_SCANCODE (0x0004) // Indicates a Keyboard Event (section 2.2.8.1.1.3.1.1.1).
#define INPUT_EVENT_UNICODE  (0x0005) // Indicates a Unicode Keyboard Event (section 2.2.8.1.1.3.1.1.2).
                case INPUT_EVENT_SCANCODE:
                    if ( (max-p) < 12) return ;
                    tmp1 = p[6] | p[7]<<8 ; // Flags
                    tmp2 = p[8] | p[9]<<8 ; // KeyCode
                    KeyEvent(ctx, tmp2, tmp1) ;
                    p += 12 ;
                    break ;
                case INPUT_EVENT_MOUSE:
                    if ( (max-p) < 12) return ;
                    MouseEvent(ctx, GET2_LE(p+8), GET2_LE(p+10), GET2_LE(p+6)) ;
                    p += 12 ;
                    break ;
                case INPUT_EVENT_SYNC:
        // 2-byte pad, 4-byte flags.
#define TS_SYNC_SCROLL_LOCK 0x00000001 // Indicates that the Scroll Lock indicator light SHOULD be on.
#define TS_SYNC_NUM_LOCK    0x00000002 // Indicates that the Num Lock indicator light SHOULD be on.
#define TS_SYNC_CAPS_LOCK   0x00000004 // Indicates that the Caps Lock indicator light SHOULD be on.
#define TS_SYNC_KANA_LOCK   0x00000008 // Indicates that the Kana Lock indicator light SHOULD be on.
                    if ( (max-p) > 5)
                    {
                        uint32_t flags  = GET4_LE(p+2) ;
                        ctx->keybd.num  = flags&TS_SYNC_NUM_LOCK  ? 1 : 0 ;
                        ctx->keybd.caps = flags&TS_SYNC_CAPS_LOCK ? 1 : 0 ;
                    }
                    break ;
                default:
                    printf("Type=0x%x at t=%d\n", typ, tim) ;
                    return ;
                }
            }
        }
    }
}


static void do_request_chan_1003(ctx_rdp *ctx, u_char *p, u_char *max)
{
    // 2.2.8.1.1.1.1 Share Control Header
    /* Chan 1003: Share Control Header
     *  2-byte tot-len
     *  2-byte pdu type
     *  2-byte PDU-source
     */
    if ((max-p) < 6) return ;

#define PDUTYPE_DEMANDACTIVEPDU  0x1 // Demand Active PDU (section 2.2.1.13.1).
#define PDUTYPE_CONFIRMACTIVEPDU 0x3 // Confirm Active PDU (section 2.2.1.13.2).
#define PDUTYPE_DEACTIVATEALLPDU 0x6 // Deactivate All PDU (section 2.2.3.1).
#define PDUTYPE_DATAPDU          0x7 // Data PDU (actual type is revealed by the pduType2 field in the Share Data Header (section 2.2.8.1.1.1.2) structure).
#define PDUTYPE_SERVER_REDIR_PKT 0xA // Enhanced Security Server Redirection PDU (section 2.2.13.3.1).

    // We only want the DATA PDU
    switch (0x000f&GET2_LE(p+2))
    {
    case PDUTYPE_DATAPDU:
        do_request_pdu_data(ctx, p+6, max) ;
        break ;
    case PDUTYPE_CONFIRMACTIVEPDU:
        parse_capability(ctx, p+6, max) ;
        break ;
    default:
        // Not interested!
        break ;
    }
}


static void do_rdpsnd(ctx_rdp *ctx, u_char *p, u_char *max, int is_up)
{
    void *replay_snd_alloc() ;
    void reply_snd_proc(void *, u_char *, u_char *, int) ;
    if (!DO_SOUND(ctx)) return ;
    if (!ctx->sound)
    {
        ctx->sound = replay_snd_alloc() ;
        if (!ctx->sound) return ;
    }
    reply_snd_proc(ctx->sound, p, max, is_up) ;
}


static void do_rdpdr(ctx_rdp *ctx, u_char *p, u_char *max, int is_up)
{
    void replay_chan_rdpdr(u_char *p, u_char *max, int is_up) ;
    if (DO_RDPDR(ctx)) replay_chan_rdpdr(p,max,is_up) ;
}


static void do_clipboard(ctx_rdp *ctx, u_char *p, u_char *max, int is_up)
{
    char name[256] ;
    int fd, len, ii ;

    // Write to disk
    if ( CLIP2DISK(ctx) &&
         (8 < (max-p)) &&
         (0x00010005 == GET4_LE(p)) )
    {
        // FIXME: There is probably a better way to handle clipboard
        len = (int)GET4_LE(p+4) ;
        p += 8 ;
        if ( (0 < len) && ((p+len) <= max))
        {
            sprintf(name,"clip-%08d-%s",
                    ctx->clip_num++,
                    is_up?"up":"down") ;
            fd = open(name,O_WRONLY|O_CREAT,0666) ;
            if (fd)
            {
                if (CLIP16LE(ctx))
                    for (ii=0 ; ii<len ; ii += 2)
                        write(fd, p+ii, 1) ;
                else
                    write(fd, p, len) ;
                close(fd) ;
            }
        }
    }
}


static const char *do_chan_data(ctx_rdp *ctx, u_char *p, u_char *max, int chan, int is_up)
{
    // 2.2.6.1.1 Channel PDU Header (CHANNEL_PDU_HEADER)
    /* Non channel 1003:
     *  length(4)
     *  flags(4)  Includes compression control
     */
#define CHANNEL_FLAG_FIRST         0x00000001 // Indicates that the chunk is the first in a sequence.
#define CHANNEL_FLAG_LAST          0x00000002 // Indicates that the chunk is the last in a sequence.
#define CHANNEL_FLAG_SHOW_PROTOCOL 0x00000010 // The Channel PDU Header MUST be visible to the application endpoint (see section 2.2.1.3.4.1).
#define CHANNEL_FLAG_SUSPEND       0x00000020 // All virtual channel traffic MUST be suspended. This flag is only valid in server-to-client virtual channel traffic. It MUST be ignored in client-to-server data.
#define CHANNEL_FLAG_RESUME        0x00000040 // All virtual channel traffic MUST be resumed. This flag is only valid in server-to-client virtual channel traffic. It MUST be ignored in client-to-server data.
#define CHANNEL_PACKET_COMPRESSED  0x00200000 // The virtual channel data is compressed. This flag is equivalent to MPPC bit C (for more information see [RFC2118] section 3.1).
#define CHANNEL_PACKET_AT_FRONT    0x00400000 // The decompressed packet MUST be placed at the beginning of the history buffer. This flag is equivalent to MPPC bit B (for more information see [RFC2118] section 3.1).
#define CHANNEL_PACKET_FLUSHED     0x00800000 // The decompressor MUST reinitialize the history buffer (by filling it with zeros) and reset the HistoryOffset to zero. After it has been reinitialized, the entire history buffer is immediately regarded as valid. This flag is equivalent to MPPC bit A (for more information see [RFC2118] section 3.1). If the CHANNEL_PACKET_COMPRESSED (0x00200000) flag is also present, then the CHANNEL_PACKET_FLUSHED flag MUST be processed first.
#define CompressionTypeMask        0x000F0000 // Indicates the compression package which was used to compress the data. See the discussion which follows this table for a list of compression packages.

    int len   = (int)GET4_LE(p) ;
    int flags = (int)GET4_LE(p+4) ;
    p += 8 ;

    if (DBG_CHAN(ctx))
    {
        if (is_up) printf(">> Chan-%d", chan) ;
        else       printf("<< Chan-%d", chan) ;
        se_out(": ",p-8,max) ;
    }

    if (flags&CHANNEL_PACKET_COMPRESSED)
    {
        if (is_up)
        {
            int play_request_decompress(uint8_t **p, uint8_t **max, int flags) ;
            if (0==play_request_decompress(&p, &max, 255&(flags>>16)))
                return "play_request_decompress failed." ;
        }
        else
        {
            int play_response_decompress(uint8_t **, uint8_t **, int) ;
            if (0==play_response_decompress(&p, &max, 255&(flags>>16)))
                return "play_response_decompress failed." ;
        }
        if (DBG_CHAN(ctx))
            se_out("       -------> Decompressed: ", p, max) ;
    }

    if ( (flags&CHANNEL_FLAG_FIRST) && (flags&CHANNEL_FLAG_LAST))
    {
        if (len != (max-p))
            return "Bad message length for complete message" ;
    }
    else
    {
        // Partial message. Glue them together.
        int dlen = max-p ;
        if (flags&CHANNEL_FLAG_FIRST)
        {
            if (ctx->chan_data.buff) free(ctx->chan_data.buff) ;
            ctx->chan_data.buff = ctx->chan_data.bptr = malloc(len) ;
            ctx->chan_data.blen = len ;
        }
        if (!ctx->chan_data.buff)
            return "Missing buffer. Malloc failed??" ;
        if (ctx->chan_data.blen != len)
            return "Inconsistent lengths for buffer" ;
        if ( (ctx->chan_data.buff+ctx->chan_data.blen) < (ctx->chan_data.bptr+dlen) )
            return "Not enough buffer space for payload" ;
        memcpy(ctx->chan_data.bptr, p, dlen) ;
        ctx->chan_data.bptr += dlen ;
        if (!(flags&CHANNEL_FLAG_LAST)) return 0 ; // More to come later
        if (ctx->chan_data.bptr != (ctx->chan_data.buff+ctx->chan_data.blen))
            return "Buff end flagged with more data expected" ;
        p   = ctx->chan_data.buff ;
        max = ctx->chan_data.buff+ctx->chan_data.blen ;
    }

    if (DBG_CHAN(ctx))
    {
        if (is_up) printf(">> Chan-%d", chan) ;
        else       printf("<< Chan-%d", chan) ;
        se_out(" complete: ",p,max) ;
    }

    if (chan == ctx->clip_ch)
        do_clipboard(ctx,p,max,is_up) ;
    else if (chan == ctx->rdpdr_ch)
        do_rdpdr(ctx, p,max,is_up) ;
    else if (chan == ctx->rdpsnd_ch)
        do_rdpsnd(ctx,p,max,is_up) ;

    return 0 ;
}


static void do_request_chan_data(ctx_rdp *ctx, u_char *p, u_char *max, int chan)
{
    const char *msg = do_chan_data(ctx, p, max, chan, 1) ;
    if (msg)
        printf("ERROR: do_request_chan_data: do_chan_data failed: %s\n", msg) ;
}


static void do_response_chan_data(ctx_rdp *ctx, u_char *p, u_char *max, int chan)
{
    const char *msg = do_chan_data(ctx, p, max, chan, 0) ;
    if (msg)
        printf("ERROR: do_response_chan_data: do_chan_data failed: %s\n", msg) ;
}


static void do_security_exchange(ctx_rdp *ctx, uint8_t *p, uint8_t *max)
{
    int play_crypt_init(ctx_rdp *) ;
    int len ;
    int got_cr = 0 ;
    priv_key *active_priv = (priv_key *)ctx->active_priv ;

    // securityExchangePDU : 4-byte len followed by encrypted RAND
    if (active_priv)
    {
        // Need to extract the client random
        uint8_t result[256] ;
        BIGNUM enc,dec ;
        do // do..while(0) so we can use break.
        {
            if ( (p+30) > max) break ;
            len = p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24 ;
            p += 4 ;
            if ( (p+len) != max) break ;
            reverse_buf(p, len) ;
            BN_init(&enc) ;
            BN_init(&dec) ;
            BN_bin2bn(p, len, &enc) ;
            BN_mod_exp(&dec, &enc, &active_priv->priv, &active_priv->mod, bn_ctx) ;
            len = BN_bn2bin(&dec, result) ;
            BN_free(&enc) ;
            BN_free(&dec) ;
            if (SEC_RANDOM_SIZE != len)
            {
                // Failed :(
                printf("ERROR: Failed to decrypted the client random.\n") ;
                break ;
            }
            reverse_buf(result, len) ;
            memcpy(ctx->client_random, result, len) ;
        //  printf("Successfully decrypted the client random.\n") ;
            got_cr = 1 ;
        } while (0) ;
    }

    // Hopefully we now have the client random.
    if (0==got_cr)
    {
        printf("===> Failed to find/extract client random.\n") ;
        return ;
    }
 // printf("Calling: play_crypt_init..\n") ;
    len = play_crypt_init(ctx) ;
    if (warning && (0==len)) printf("WARNING: Crypt-Init failed.\n") ;
 // printf("PlayCryptInit: return=%d (1=good!)\n", len) ;
    DONE_HS(ctx) = 1 ;
}


uint8_t *play_request_decrypt(uint8_t *, uint8_t *, uint16_t flags) ;

static void do_request_rdp(ctx_rdp *ctx, u_char *p, u_char *max, int init, int chan)
{
    if (0==ctx->ssl_mode)
    {
        int ii, flo, fhi ;

        /* 2.2.8.1.1.2.1 Basic (TS_SECURITY_HEADER)
         *  FlagsLow(2)
         *  FlagsHi(2) (only valid if FlagsLow indicates it is) (never used!)
         */
        if ( (p+4) >= max) return ;

        // Low Flags:
#define SEC_EXCHANGE_PKT       0x0001 // Indicates that the packet is a Security Exchange PDU (section 2.2.1.10). This packet type is sent from client to server only. The client only sends this packet if it will be encrypting further communication and Standard RDP Security mechanisms (section 5.3) are in effect.
#define SEC_TRANSPORT_REQ      0x0002 // Indicates that the packet is an Inititiate Multitransport Request PDU (section 2.2.15.1).
#define RDP_SEC_TRANSPORT_RSP  0x0004 // Indicates that the packet is an Inititiate Multitransport Error PDU (section 2.2.15.2).
#define SEC_ENCRYPT            0x0008 // Indicates that the packet is encrypted.
#define SEC_RESET_SEQNO        0x0010 // This flag is not processed by any RDP clients or servers and MUST be ignored.
#define SEC_IGNORE_SEQNO       0x0020 // This flag is not processed by any RDP clients or servers and MUST be ignored.
#define SEC_INFO_PKT           0x0040 // Indicates that the packet is a Client Info PDU (section 2.2.1.11). This packet type is sent from client to server only. If Standard RDP Security mechanisms are in effect, then this packet MUST also be encrypted.
#define SEC_LICENSE_PKT        0x0080 // Indicates that the packet is a Licensing PDU (section 2.2.1.12).
#define SEC_LICENSE_ENCRYPT_CS 0x0200 // Indicates to the client that the server is capable of processing encrypted licensing packets. It is sent by the server together with any licensing PDUs (section 2.2.1.12).
#define SEC_LICENSE_ENCRYPT_SC 0x0200 // Indicates to the server that the client is capable of processing encrypted licensing packets. It is sent by the client together with the SEC_EXCHANGE_PKT flag when sending a Security Exchange PDU (section 2.2.1.10).
#define SEC_REDIRECTION_PKT    0x0400 // Indicates that the packet is a Standard Security Server Redirection PDU (section 2.2.13.2.1) and that the PDU is encrypted.
#define SEC_SECURE_CHECKSUM    0x0800 // Indicates that the MAC for the PDU was generated using the "salted MAC generation" technique (see section 5.3.6.1.1). If this flag is not present, then the standard technique was used (sections 2.2.8.1.1.2.2 and 2.2.8.1.1.2.3).
#define SEC_AUTODETECT_REQ     0x1000 // Indicates that the packet is an Auto-Detect Request PDU (section 2.2.14.3) or that the autoDetectReqData field is present. This flag MUST NOT be present if the PDU containing the security header is being sent from client to server.
#define SEC_AUTODETECT_RSP     0x2000 // Indicates that the packet is an Auto-Detect Response PDU (section 2.2.14.4). This flag MUST NOT be present if the PDU containing the security header is being sent from server to client.
#define SEC_FLAGSHI_VALID      0x8000 // Indicates that the flagsHi field contains valid data. If this flag is not set, then the contents of the flagsHi field MUST be ignored.

        flo = GET2_LE(p) ;
        fhi = GET2_LE(p+2) ;
        p  += 4 ;

 //     printf(">> Slow-RDP Channel:%d Initiator:%d F=%04x %04x", chan, init, flo, fhi) ;
 //     se_out(": ", p, max) ;

        if (flo&SEC_EXCHANGE_PKT)
        {
            // securityExchangePDU. Last chance to get client random!
            do_security_exchange(ctx, p, max) ;
            return ;
        }

        if (flo&SEC_ENCRYPT)
        {
            p = play_request_decrypt(p,max,(uint16_t)flo) ;
            if (!p)
            {
                printf("ERROR: Request decrypt failed!\n") ;
                return ;
            }
            if (DBG_DEC(ctx)) se_out(">> DEC: ",p,max) ;
        }

        if ( (flo&SEC_INFO_PKT) ||
             (flo&SEC_LICENSE_PKT) ||
             (flo&SEC_REDIRECTION_PKT) )
        {
  //        printf(">> RDP HS LO=%04x HI=%04x", flo, fhi) ;
  //        se_out(": ", p, max) ;
            return ; // Not interested!
        }
    }

    if (1003==chan)
        do_request_chan_1003(ctx,p,max) ;
    else
        do_request_chan_data(ctx, p,max,chan) ;
}


static void do_request_mcs(ctx_rdp *ctx, u_char *p, u_char *max)
{
    // 25 = Send Data
    if ( (max-p)>10 &&
         p[0]==127 && // Application
         p[1]==101 )  // connect-initial
    {
        if ( p[2]==0x82)
        {
            int len=p[3]<<8 | p[4] ;
            p += 5 ;
            if ( (p+len) <= max)
                do_con_init(ctx, p, p+len) ;
        }
    }
    else if ( (max-p)>8 &&
              0x64 == (p[0]&0xfc) && // sendDataRequest
              0x70 == p[5])
    {
        // sendDataRequest
        int len ;
        int init = p[1]<<8 | p[2] ;
        int chan = p[3]<<8 | p[4] ;
        p += 6 ;
        len = *p++ ;
        if (len&0x80)
            // 15-bit length
            len = ((len&0x7f)<<8) | *p++ ;
        if ( (p+len) > max)
        {
            printf("Too long!\n") ;
            return ;
        }
        if (warning && ((p+len) < max))
            printf("WARNING: Send-Data of length %d, slops=%d\n", len, (int)(max-p-len)) ;
        do_request_rdp(ctx,p,p+len,init,chan) ;
    }
    else if ( 0x04 == (p[0]&0xfc) )
    {
        // erectDomainRequest
    }
    else if ( 0x28 == (p[0]&0xfc) )
    {
        // attachUserRequest
    }
    else if ( 0x38 == (p[0]&0xfc) )
    {
        // channelJoinRequest
    }
 // else
 //     se_out(">> MCS-Payload?? ", p, (p+10)<max?p+10:max) ;
}


static int do_request_tpkt(ctx_rdp *ctx, u_char *p, u_char *max)
{
    int len = max-p ;

    if (DBG_RAW(ctx)) se_out(">> RAW: ", p-4, max) ;

    if (len<3)
    {
        printf("do_request_tpkt: Bad length\n") ;
        return 1 ;
    }
    if (p[0]==0x02 &&
        p[1]==0xf0 &&
        p[2]==0x80)
    {
 //     printf("ISO-Data\n") ;
        do_request_mcs(ctx, p+3, max) ;
 //     return 1 ;
    }
    else if ((p[1]&0xf0)==0xe0)
    {
        // Connect Request
 //     printf("ISO-Connect\n") ;
    }
    else if (p[1]==0x80)
    {
        // Disconnect
 //     printf("ISO-DR Disconnect Request\n") ;
    }
    else
    {
        se_out("==> Unknown ISO packet! ",p,max) ;
        return 1 ;
    }
    return 0 ;
}


static int do_request_fast(ctx_rdp *ctx, u_char *p, u_char *max)
{
    int hlen   = 2 ;
    int count = 0xf & (p[0]>>2) ;

    if (DBG_RAW(ctx)) se_out(">> RAW: ", p, max) ;

    if (0x80&p[1]) ++hlen ;

    if ( (p[0]&0x80) && 0==ctx->ssl_mode)
    {
        p = play_request_decrypt(p+hlen,max,p[0]&0x40?SEC_SECURE_CHECKSUM:0) ;
        if (!p)
        {
            printf("do_request_fast: decrypt failed.\n") ;
            return 1 ;
        }
    }
    else
        p += hlen ;
    if (0==count) count = *p++ ;
 // printf("  FastPath(count=%d)\n", count) ;
 // se_out(": ",p,max) ;
    for ( ; count ; --count)
    {
        int code, flags ;
        if (p >= max)
        {
            printf("do_request_fast: Data parse error.\n") ;
            return 1 ;
        }
        code  = p[0]>>5 ;
        flags = p[0]&0x1f ;
    //  printf("Event: code:%d Flags: %d (%d bytes left)\n", code, flags, (int)(max-p)) ;
        switch(code)
        {
        case 0: // 2.2.8.1.2.2.1 Fast-Path Keyboard Event
            // Keyboard: 2 bytes: code keyCode
            // FASTPATH_INPUT_KBDFLAGS_RELEASE  0x01
            // FASTPATH_INPUT_KBDFLAGS_EXTENDED 0x02
            if ( (p+2) > max) return 1 ;
            KeyEvent(ctx,
                     p[1],
                     ((flags&1)?0xc000:0) |
                     ((flags&2)?0x0100:0) ) ; // Change 2-bit flags to full extended (slowpath) flags
       //   if (0 == (flags&1))
       //       printf("KeyCode: (flags:0x%x) %s-%d\n", flags, (flags&1)?"Up":"Down", (int)p[1]) ;
            p += 2 ;
            break ;
        case 1: // MouseMove: 7 bytes: code flag1 flag2 x1 x2 y1 y2
            if ( (p+7) > max) return 1 ;
            MouseEvent(ctx, GET2_LE(p+3), GET2_LE(p+5), GET2_LE(p+1)) ;
            was_order = 1 ; // Delay for rendering update
            p += 7 ;
            break ;
        case 3: // Sync. For Capslock etc.
            ctx->keybd.num  = flags&2 ? 1 : 0 ;
            ctx->keybd.caps = flags&4 ? 1 : 0 ;
         // printf("Sync Flags:") ;
         // if (flags&1) printf(" ScrollLock") ;
         // if (flags&2) printf(" NumLock") ;
         // if (flags&4) printf(" CapsLock") ;
         // if (flags&8) printf(" KanaLock") ;
         // printf("(0x%02x)\n", flags) ; fflush(stdout) ;
            p += 1 ;
            break ;
        default:
            if (warning) printf("do_request_fast: Failed code: %d\n", code) ;
            return 1 ;
        }
    }
    if (warning && (p!=max)) se_out("WARNING: do_request_fast: trailing data:", p, max) ;
    return 0 ;
}


static int do_response_fast(ctx_rdp *ctx, u_char *p, u_char *max)
{
    uint8_t *play_response_decrypt(uint8_t *, uint8_t *, uint16_t) ;
    int play_response_fast(uint8_t *, uint8_t *, uint8_t) ;

    uint8_t header = p[0] ;
    int hlen       = 2 ;

    if (DBG_RAW(ctx)) se_out("<< RAW: ", p, max) ;
    if (SKIP_GFX(ctx)) return 1 ;

    if (0x80&p[1]) ++hlen ; // 2-byte length
    if ( (p[0]&0x80) && 0==ctx->ssl_mode)
    {
 //     se_out("<< FastDataBeforeDecrypt: ",p,max) ;
        p = play_response_decrypt(p+hlen, max, p[0]&0x40?SEC_SECURE_CHECKSUM:0) ;
        if (!p)
        {
            printf("do_response_fast: decrypt failed.\n") ;
            exit(0) ;
            return 1 ;
        }
        if (DBG_DEC(ctx)) se_out("<< DEC: ",p,max) ;
    }
    else
        p += hlen ;
    if (0==play_response_fast(p,max,header))
    {
        printf("ERROR: do_response_fast: play_response_fast failed.\n") ;
        return 1 ;
    }
    return 0 ;
}


static void do_response_rdp(ctx_rdp *ctx, u_char *p, u_char *max, int chan)
{
    uint8_t *play_response_decrypt(uint8_t *, uint8_t *, uint16_t) ;
    int play_response_slow(uint8_t *, uint8_t *, int, int) ;
    int flo, fhi ;
    if (0==ctx->ssl_mode)
    {
        if ( (max-p) <= 4) return ;
        flo = GET2_LE(p) ;
        fhi = GET2_LE(p+2) ;
        p  += 4 ;
        if (flo&SEC_ENCRYPT)
        {
            p = play_response_decrypt(p, max, flo&SEC_SECURE_CHECKSUM) ;
            if (!p)
            {
                printf("do_response_rdp: decrypt failed.\n") ;
                exit(0) ;
            }
 //         se_out("<<  Decrypt: ", p, max) ;
        }

        // Skip things we don't care about
        if (flo&SEC_LICENSE_PKT) return ;
        if (flo&SEC_REDIRECTION_PKT) return ;
    }
    if (1003 == chan)
    {
        if (0==play_response_slow(p,max,chan,flo) && warning)
            printf("WARNING: do_response_rdp: play_response_slow failed.\n") ;
    }
    else
        do_response_chan_data(ctx,p,max,chan) ;
}


static void do_response_mcs(ctx_rdp *ctx, u_char *p, u_char *max)
{
    if ( (p+20) < max &&
         0x7f == p[0] &&
         0x66 == p[1]  )
    {
        int len ; //= p[3] << 8 | p[4] ;
        p += 2 ;
        GET_LEN(len) ;
        if ( (p+len) == max)
            do_con_resp(ctx,p,max) ;
  //    printf("MCS-connect-response of len %d (out of %d)\n", len, (int)(max-p)) ;
        return ;
    }
    switch (p[0]&0xfc)
    {
    case 0x08: // ??
    case 0x20: // disconnectProviderUltimatum
    case 0x2c: // AttachUserConfirm
    case 0x3c: // JoinChannelConfirm
        return ;
    case 0x68:
        if ((max-p) > 6)
        {
            // sendDataIndication 0x68, 2-byte initiator, 2-byte channel, 1-byte flags, length, RDP data
            int chan, init, len ;
            init = p[1]<<8 | p[2] ;
            chan = p[3]<<8 | p[4] ;
            p += 6 ;
            if (0x80&p[0])
            {
                len = 0x7fff & (p[0]<<8|p[1]) ;
                p += 2 ;
            }
            else
                len = *p++ ;
            if ((p+len) > max)
            {
                printf("len=%d got=%d: ", (int)len, (int)(max-p)) ;
                se_out("ERROR: Short data for sendDataIndication: ",p,max) ;
                return ;
            }
            do_response_rdp(ctx,p,max,chan) ;
            return ;
        }
        break ;
    }
    se_out("ERROR: do_response_mcs: Unknown msg: ",p,max) ;
}


static int do_response_tpkt(ctx_rdp *ctx, u_char *p, u_char *max)
{
    if (DBG_RAW(ctx)) se_out("<< RAW: ", p-4, max) ;
    if ( (SKIP_GFX(ctx)) && DONE_HS(ctx)) return 1 ;

    if ( (p+4)<max &&
         0x02 == p[0] &&
         0xf0 == p[1] &&
         0x80 == p[2])
    {
        do_response_mcs(ctx, p+3, max) ;
    }
    else if ((p[1]&0xf0)==0xd0)
    {
        // Connect Confirm
        // See 2.2.1.2.1 RDP Negotiation Response for MS extensions used here
        if (14==p[0] &&   // Length Indicator
            15==(max-p) &&
            2 ==p[7] &&   // Type = 0x02 (TYPE_RDP_NEG_RSP)
            8 ==p[9] &&   // Len = 8 (Low)
            0 == p[10] && // Len = 8 (High)
            p[11])        // RDP is 0. Anything else indicates SSL
        {
            // Server wants SSL
            printf("RDP SSL MODE Requested by server!!\n") ;
            ctx->ssl_mode = 1 ;
        }
    }
    return 0 ;
}


typedef struct {
    int mode ;
    int need ;
    int got ;
    u_char buf[65540] ;
} my_buf ;


// Used by buffering after SSL (if needed) to get the message length.
// May be TPKT or fast-path
static int msg_len(void *vctx, const uint8_t *p, size_t len)
{
    ctx_rdp *ctx = (ctx_rdp *)vctx ;
    if (1==ctx->ssl_mode && len>1)
    {
        int play_pre_init(ctx_rdp *), play_post_init(ctx_rdp *) ;
        if (0x30==p[0])
        {
            // Valid: 00..7f,81,82   Could have 83, but NO! We don't.
            if (0x82  < p[1]) return -1 ;
            if (0x80 == p[1]) return -1 ;
            if (0x80&p[1])
            {
                if (len < (2+(0x7f&p[1])))
                    // Need more bytes for length field
                    return 0 ;
                if (0x81 == p[1])
                    return 3+p[2] ;
                return 4+(p[2]<<8 | p[3]) ;
            }
            else
                return 2+p[1] ;
        }
        ++ctx->ssl_mode ;
        play_pre_init(ctx) ;
        play_post_init(ctx) ;
    }
    if (len<4)
        return 0 ;
    else if (3==p[0] && 0==p[1])
        return p[2]<<8|p[3] ;
    else if (0x80&p[1])
        return 0x7fff & (p[1]<<8|p[2]) ;
    else
        return p[1] ;
}


// Client messages come in here. May have been processed by SSL first.
static void old_request(void *vh,
                        const u_char *p,
                        size_t len)
{
    ctx_rdp *ctx = (ctx_rdp *)vh ;
    buffer_add(ctx->req_buf2, p, len) ;
    while (0!=(p=buffer_next(ctx->req_buf2, &len)))
    {
        uint8_t use[65536] ;
    //  if (DBG_DEC(ctx)) se_out(">> DEC: ",p,p+len) ;
        if (1==ctx->ssl_mode) continue ;
        memcpy(use,p,len) ;
        if (3==p[0]) do_request_tpkt(ctx, use+4, use+len) ;
        else         do_request_fast(ctx, use,use+len) ;
    }
}


// Server messages come in here. May have been processed by SSL first.
static void old_response(void *vh,
                         const u_char *p,
                         size_t len)
{
    ctx_rdp *ctx = (ctx_rdp *)vh ;
    buffer_add(ctx->res_buf2, p, len) ;
    while (0!=(p=buffer_next(ctx->res_buf2, &len)))
    {
        uint8_t use[65536] ;
        if (1==ctx->ssl_mode) { if (DBG_DEC(ctx)) se_out("<< DEC: ",p,p+len) ; continue ; }
        memcpy(use,p,len) ;
        if (3==p[0]) do_response_tpkt(ctx, use+4,use+len) ;
        else         do_response_fast(ctx, use, use+len) ;
    }
}


//  This is used to work out message length.
static int getBlen(void *vctx, const uint8_t *p, size_t len)
{
    ctx_rdp *ctx = (ctx_rdp *)vctx ;
    if (len<4) return 0 ;

    // SSL?
    if (ctx->ssl_mode)
    {
        if (len < 5) return 0 ;
        if ( (0x13 < p[0]) && (p[0] < 0x18) &&
             (0x03 == p[1]) &&
             (p[2] < 4) )
            return 5 + (p[3]<<8|p[4]) ;
        return -1 ;
    }

    // TPKT?
    if (3==p[0] && 0==p[1])
        return p[2]<<8 | p[3] ;

    // Must be Fast-path
    if (p[1]&0x80)
        return 0x7fff & (p[1]<<8 | p[2]) ;
    return p[1] ;
}


// Raw client data (from TCP stream?) is processed here.
void librdp_request(void *vc,
                    const u_char *p,
                    size_t len)
{
    ctx_rdp *ctx = (ctx_rdp *)vc ;
    if (!ctx) return ;
    if (DBG_RAW(ctx)) se_out(">> DATA: ", p, p+len) ;
    (void)buffer_add(ctx->req_buf1,p,len) ;
    while (0!=(p=buffer_next(ctx->req_buf1,&len)))
        if (len)
        {
            if (ctx->ssl_mode) ssl_proc_client(ctx->ssl_h,p,len) ;
            else               old_request(vc,p,len) ;
        }
}


// Raw server data (from TCP stream?) is processed here.
void librdp_response(void *vc,
                     const u_char *p,
                     size_t len)
{
    ctx_rdp *ctx = (ctx_rdp *)vc ;
    if (!ctx) return ;
    if (DBG_RAW(ctx)) se_out("<< DATA: ", p, p+len) ;
    (void)buffer_add(ctx->res_buf1,p,len) ;
    while (0!=(p=buffer_next(ctx->res_buf1,&len)))
        if (len)
        {
            if (ctx->ssl_mode) ssl_proc_server(ctx->ssl_h,p,len) ;
            else               old_response(vc,p,len) ;
        }
}


void librdp_sslkey(const char *keyfile)
{
    (void)keyring_add(ssl_kr, keyfile) ;
}


static void librdp_init()
{
static int do_events  = 1 ;
    static const char * larg[3] ;

    ssl_kr = keyring_create() ;

    // Start event handling routine
    if (do_events)
    {
        pthread_t th ;
        pthread_create(&th, 0, thred, 0) ;
    }

    // Prep and call the old main entrypoint
    larg[0] = "cybran" ;
    larg[1] = "chan" ;
    larg[2] = 0 ;
    was_main(2, larg) ;
    if (do_events)
        XInitThreads() ;
}


void librdp_stop()
{
    if (ssl_kr) keyring_free(ssl_kr) ; ssl_kr = 0 ;
}
