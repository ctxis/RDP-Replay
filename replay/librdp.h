#ifndef LIBRDP_H
#define LIBRDP_H

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

void  librdp_stop() ;
void *librdp_new() ;
void  librdp_del(void *) ;
void  librdp_keys(const char *keyfile) ;
void  librdp_key_raw(const char *keyfile) ;
void  librdp_sslkey(const char *keyfile) ;

void  librdp_clipboard_16le(void *) ;
void  librdp_debug_capabilities(void *) ;
void  librdp_debug_channels(void *) ;
void  librdp_debug_crypt(void *) ;
void  librdp_debug_raw(void *) ;
void  librdp_output(void *, const char *) ;
void  librdp_save_clipboard(void *) ;
void  librdp_set_ts(void *, const struct timeval *) ;
void  librdp_sound(void *) ;
void  librdp_rdpdr(void *) ;
void  librdp_show_cursor(void *, int) ;
void  librdp_show_keys(void *) ;
void  librdp_sw_gdi(void *) ;

/* Request (client-to-server) data should be sent here */
void librdp_request(void *, const uint8_t *p, size_t len) ;

/* Response (server-to-client) data should be sent here */
void librdp_response(void *, const uint8_t *p, size_t len) ;



#ifdef __rdp_private__

#define SEC_RANDOM_SIZE (32)
#define NUM_CHANS (8)

enum { RF_DONE_HS, RF_SKIP_GFX, RF_DBG_CAPS, RF_DBG_CHAN, RF_DBG_RAW, RF_DBG_DEC, RF_SHOW_KEYS, RF_CLIP2DISK, RF_CLIP16LE, RF_SW_GDI, RF_SOUND, RF_RDPDR, RF_MAX } ;
#define CTX_FLAG(A,B) (A)->flags[B]
#define DONE_HS(A)    CTX_FLAG(A,RF_DONE_HS)
#define SHOW_KEYS(A)  CTX_FLAG(A,RF_SHOW_KEYS)
#define SKIP_GFX(A)   CTX_FLAG(A,RF_SKIP_GFX)
#define DBG_CAPS(A)   CTX_FLAG(A,RF_DBG_CAPS)
#define DBG_CHAN(A)   CTX_FLAG(A,RF_DBG_CHAN)
#define DBG_RAW(A)    CTX_FLAG(A,RF_DBG_RAW)
#define DBG_DEC(A)    CTX_FLAG(A,RF_DBG_DEC)
#define CLIP2DISK(A)  CTX_FLAG(A,RF_CLIP2DISK)
#define CLIP16LE(A)   CTX_FLAG(A,RF_CLIP16LE)
#define SW_GDI(A)     CTX_FLAG(A,RF_SW_GDI)
#define DO_SOUND(A)   CTX_FLAG(A,RF_SOUND)
#define DO_RDPDR(A)   CTX_FLAG(A,RF_RDPDR)

typedef struct
{
    uint8_t     flags[RF_MAX] ; // Option Flags
    void       *req_buf1 ;      // Request buffer (SSL)
    void       *res_buf1 ;      // Response buffer (SSL)
    void       *req_buf2 ;      // Request buffer (RDP)
    void       *res_buf2 ;      // Response buffer (RDP)
    void       *ssl_h ;         // SSL handle
    void       *active_priv ;   // Private key
    uint8_t     client_random[SEC_RANDOM_SIZE] ;
    uint8_t     server_random[SEC_RANDOM_SIZE] ;
    uint32_t    use_enc_type ;
    int         ssl_mode ;      // SSL mode tracking
    int         clip_ch ;       // cliprdr (Clipboard) channel
    int         rdpdr_ch ;      // rdprd channel
    int         rdpsnd_ch ;     // rdpsnd channel
    void       *sound ;         // Sound control
    int         clip_num ;      // Clipboard transaction number
    struct
    {
        uint8_t pressed[104] ;  // Keys down tracking
        uint8_t caps ;          // CAPS-Lock
        uint8_t num ;           // NUM-Lock
    } keybd;
    struct
    {
        // FIXME: Separate buffers for up and down??
        uint8_t *buff ;
        uint8_t *bptr ;
        int      blen ;
    } chan_data ;
    struct
    {
        uint8_t name[12] ;
        uint16_t num ;
    } Channels[NUM_CHANS] ;
} ctx_rdp ;
#endif

#endif
