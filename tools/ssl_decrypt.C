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

#include "ssl_decrypt.h"

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <openssl/err.h>

#include <stdexcept>


// Things we need from inside OpenSSL
extern "C"
{
    void ssl3_init_finished_mac(SSL *s) ;
    int ssl3_do_change_cipher_spec(SSL *s) ;
    void ssl3_finish_mac(SSL *s, const unsigned char *buf, int len) ;
 // unsigned long ERR_get_error_line(const char **file, int *line) ;
 // unsigned long ERR_get_error(void) ;
 // char *ERR_error_string(unsigned long e, char *ret) ;

    // From SSL private include file:
    typedef struct ssl3_enc_method
    {
        int (*enc)(SSL *, int);
        int (*mac)(SSL *, unsigned char *, int);
        int (*setup_key_block)(SSL *);
        int (*generate_master_secret)(SSL *, unsigned char *, unsigned char *, int);
        int (*change_cipher_state)(SSL *, int);
        int (*final_finish_mac)(SSL *,  const char *, int, unsigned char *);
        int finish_mac_length;
        int (*cert_verify_mac)(SSL *, int, unsigned char *);
        const char *client_finished_label;
        int client_finished_label_len;
        const char *server_finished_label;
        int server_finished_label_len;
        int (*alert_value)(int);
        int (*export_keying_material)(SSL *, unsigned char *, size_t,
                                      const char *, size_t,
                                      const unsigned char *, size_t,
                                      int use_context);
    } SSL3_ENC_METHOD;

}


// The "C" interface implementation - just wrappers for the objects.
extern "C"
{
    void *keyring_create()
    {
        try {
            return new keyring ;
        } catch (...){
            return 0 ;
        }
    }
    int keyring_add(void *vkr, const char *filename)
    {
        keyring *kr = reinterpret_cast<keyring *>(vkr) ;
        return kr->add(filename) ;
    }
    void keyring_free(void *vkr)
    {
        keyring *kr = reinterpret_cast<keyring *>(vkr) ;
        delete kr ;
    }
    struct void_ssl
    {
        struct MyPro : public processor
        {
            void (*f_client)(void *, const uint8_t *, size_t) ;
            void (*f_server)(void *, const uint8_t *, size_t) ;
            void *vh ;
            bool client(const uint8_t *p, size_t l) { f_client(vh, p, l) ; }
            bool server(const uint8_t *p, size_t l) { f_server(vh, p, l) ; }
        } proc ;
        ssl_processor ssl ;
        void_ssl(void (*f_c)(void *, const uint8_t *, size_t),
                 void (*f_s)(void *, const uint8_t *, size_t)) :
                ssl(proc)
        {
            proc.vh       = 0 ;
            proc.f_client = f_c ;
            proc.f_server = f_s ;
        }
    } ;
    void *ssl_proc_create(void (*client)(void *, const uint8_t *, size_t),
                          void (*server)(void *, const uint8_t *, size_t),
                          void *vkr)
    {
        keyring *kr = reinterpret_cast<keyring *>(vkr) ;
        void_ssl *rv = new void_ssl(client, server) ;
        rv->ssl.set_keyring(kr) ;
        return rv ;
    }
    void ssl_set_user(void *vssl, void *ud)
    {
        void_ssl *ssl = reinterpret_cast<void_ssl *>(vssl) ;
        ssl->proc.vh = ud ;
    }
    int ssl_proc_client(void *vssl, const uint8_t *data, size_t len)
    {
        void_ssl *ssl = reinterpret_cast<void_ssl *>(vssl) ;
        return (int)ssl->ssl.client(data, len) ;
    }
    int ssl_proc_server(void *vssl, const uint8_t *data, size_t len)
    {
        void_ssl *ssl = reinterpret_cast<void_ssl *>(vssl) ;
        return (int)ssl->ssl.server(data, len) ;
    }
    int ssl_proc_ok(void *vssl)
    {
        void_ssl *ssl = reinterpret_cast<void_ssl *>(vssl) ;
        return ssl->ssl.error() ;
    }
    void ssl_proc_free(void *vssl)
    {
        void_ssl *ssl = reinterpret_cast<void_ssl *>(vssl) ;
        delete ssl ;
    }
}


// Macros for ASN.1 BER parsing. All expect
//   Return false on error
//   p    to be the data pointer
//   max  to be the pointer to the first invalid byte after p
#define GET_LEN(A) \
    do { \
        if (p >= max) return false ; \
        if (p[0]&0x80) { \
            int n=0, m=(*p++)&0x7f ; \
            for( ; m ; --m) \
                n = n<<8 | (255&(*p++)) ; \
            A = n ; \
        } else \
            A = (*p++) ; \
    } while (0)
#define EXPECT(V) \
    do {\
        if (p >= max) return false ; \
        if ((*p++) != V) return false ; \
    } while (0)
#define ASN1_skip(V) \
        do {\
            size_t _l ;\
            EXPECT(V) ;\
            GET_LEN(_l) ;\
            if ((p+_l)>max) return false ;\
            p += _l ;\
        } while (0)


// This will scan and read a public key in ASN.1 BER format. Uses macros (above)
static bool read_pub(const uint8_t *p, int in_len, BIGNUM **n, BIGNUM **e)
{
    const uint8_t * max = p+in_len ;
    int len ;

    EXPECT(0x30) ;
    GET_LEN(len) ;
    if ((p+len)>max) return false ;
    EXPECT(0x02) ;
    GET_LEN(len) ;
    if ((p+len)>max) return false ;
    *n = BN_bin2bn(p, len, NULL) ;
    if (NULL==(*n)) return false ;
    p += len ;
    EXPECT(0x02) ;
    GET_LEN(len) ;
    if ((p+len)>max) return false ;
    *e = BN_bin2bn(p, len, NULL) ;
    if (!(*e))
    {
        BN_free(*n) ;
        return 0 ;
    }
    return true ;
}


// This will scan and read a cert in ASN.1 BER format. Uses macros (above)
static bool read_cert(const uint8_t *p, int in_len, BIGNUM **n, BIGNUM **e)
{
    const uint8_t * max = p+in_len ;
    int len ;

    // Overall SEQUENCE should be the whole item
    EXPECT(0x30) ;
    GET_LEN(len) ;
    if ((p+len) != max) return false ;

    // Start of signedCertificate - step into it
    EXPECT(0x30) ;
    GET_LEN(len) ;
    if ((p+len)>max) return false ;
    max = p+len ;

    if (len<30) return false ;

    if (0xa0==p[0])
        ASN1_skip(0xa0) ; // Version - optional
    ASN1_skip(0x02) ; // serialNumber
    ASN1_skip(0x30) ; // signature
    ASN1_skip(0x30) ; // issuer
    ASN1_skip(0x30) ; // validity
    ASN1_skip(0x30) ; // subject

    // Now at subjectPublicKeyInfo - step into it
    EXPECT(0x30) ;
    GET_LEN(len) ;
    max = p+len ;

    ASN1_skip(0x30) ; // algorithm
    EXPECT(0x03) ;    // Octet string??
    GET_LEN(len) ;
    max = p+len ;
    EXPECT(0x00) ;    // Padding
    return read_pub(p, max-p, n, e) ;
}


//===================================================
//========== Single RSA key implementation ==========
//===================================================

// Class for a single RSA private key.
RsaPriv::RsaPriv(const char *filename)
{
    FILE *fp = fopen(filename, "r") ;
    try {
        if (!fp) throw std::runtime_error("cannot read file") ;
        m_key = PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL) ;
        if (!m_key) throw std::runtime_error("PEM_read_RSAPrivateKey failed") ;
        fclose(fp) ;
    } catch (...) {
        if (fp) fclose(fp) ;
        throw ;
    }
}

RsaPriv::~RsaPriv()
{
    RSA_free(m_key) ;
}

bool RsaPriv::check_pub(const BIGNUM &n, const BIGNUM &e) const
{
    return (0==BN_cmp(&n,m_key->n)) && (0==BN_cmp(&e,m_key->e)) ;
}

bool RsaPriv::check_pub(const uint8_t *pub, size_t len) const
{
    BIGNUM *n, *e ;
    bool rv ;
    if (!read_pub(pub,len,&n,&e)) return false ;
    rv = check_pub(*n,*e) ;
    BN_free(n) ;
    BN_free(e) ;
    return rv ;
}

size_t RsaPriv::out_size() const
{
    return RSA_size(m_key) ;
}

int RsaPriv::decrypt(uint8_t *out, const uint8_t *in, size_t len) const
{
    return RSA_private_decrypt(len, in, out, m_key, RSA_PKCS1_PADDING) ;
}


//================================================
//========== RSA keyring implementation ==========
//================================================

//! Manage RSA private keys.
struct keyring::RSA_key
{
    RsaPriv key ;
    RSA_key *next ;
    RSA_key(const char *name) : key(name), next(0) {}
} ;

keyring::keyring() : m_keys(0) {}

keyring::~keyring()
{
    while (m_keys)
    {
        RSA_key *del = m_keys ;
        m_keys = del->next ;
        delete del ;
    }
}

bool keyring::add(const char *name)
{
    RSA_key *in ;
    try {
        in = new RSA_key(name) ;
    } catch (...) {
        return false ;
    }
    in->next = m_keys ;
    m_keys   = in ;
    return true ;
}

const RsaPriv * keyring::find(const BIGNUM &n, const BIGNUM &e) const
{
    for (RSA_key *key=m_keys ; key ; key=key->next)
        if (key->key.check_pub(n,e)) return &key->key ;
    return 0 ;
}

const RsaPriv * keyring::find(const uint8_t *pub, size_t len) const
{
    BIGNUM *n, *e ;
    const RsaPriv *rv ;
    if (!read_pub(pub,len,&n,&e)) return 0 ;
    rv = find(*n,*e) ;
    BN_free(n) ;
    BN_free(e) ;
    return rv ;
}


SSL_CTX *glob_ctx = 0 ;



//==================================================
//========== SSL Session-ID Cache ==================
//==================================================
class ssl_cache
{
    struct ssl_cache_entry
    {
        struct ssl_cache_entry *next ;
        size_t len ;
        uint8_t id[SSL3_SESSION_ID_SIZE] ;
        uint8_t key[0] ;
    } ;
    ssl_cache_entry *m_ents ;
public:
    ssl_cache()
    {
        m_ents = 0 ;
    }
    ~ssl_cache()
    {
        void *f ;
        while (m_ents) {
            f = m_ents ;
            m_ents = m_ents->next ;
            free(f) ;
        }
    }
    void add(const uint8_t *id, const uint8_t *dec, size_t len)
    {
        ssl_cache_entry *ent = (ssl_cache_entry *)malloc(sizeof(ssl_cache_entry)+len) ;
        if (ent) {
            memcpy(ent->id, id, SSL3_SESSION_ID_SIZE) ;
            memcpy(ent->key, dec, len) ;
            ent->next = m_ents ;
            ent->len  = len ;
            m_ents    = ent ;
        }
    }
    size_t find(const uint8_t *id, uint8_t **dec)
    {
        for (ssl_cache_entry *ii=m_ents ; ii ; ii=ii->next)
            if (0==memcmp(ii->id,id,SSL3_SESSION_ID_SIZE)) {
                *dec = ii->key ;
                return ii->len ;
            }
    }
} g_cache ;

//==================================================
//========== SSL processor implementation ==========
//==================================================

// Helper routine to parse SSL v2.0 client hello messages
static bool parse_2_hello(const uint8_t *p, size_t plen, uint8_t *cli_rand)
{
    if (plen < 44) return false ;
    uint32_t rlen = p[9]<<8|p[10] ;
    if (0==rlen || SSL3_RANDOM_SIZE<rlen) return false ;
    size_t skip = 11 + (p[5]<<8|p[6]) + (p[7]<<8|p[8]) ;
    if (plen < (skip+rlen)) return false ;
    if (rlen < SSL3_RANDOM_SIZE) bzero(cli_rand, SSL3_RANDOM_SIZE) ;
    memcpy(cli_rand+SSL3_RANDOM_SIZE-rlen, p+skip, rlen) ;
    return true ;
}

ssl_processor::common::common() :
        priv(0), got_cli(false), got_srv(false), got_sess_id(false)
{
}

void ssl_processor::common::set_cli(const uint8_t *cli)
{
    memcpy(cli_rand,cli,SSL3_RANDOM_SIZE) ;
    got_cli = true ;
}

void ssl_processor::common::set_srv(const uint8_t *srv, const uint8_t *cs)
{
    memcpy(srv_rand,srv,SSL3_RANDOM_SIZE) ;
    cipher[0] = cs[0] ;
    cipher[1] = cs[1] ;
    got_srv = true ;
}

void ssl_processor::common::set_sess(const uint8_t *id)
{
    memcpy(sess_id,id,SSL3_SESSION_ID_SIZE) ;
    got_sess_id = true ;
}

ssl_processor::ssl_buff::ssl_buff() :
        m_ssl(0), m_initial(true), m_can_decrypt(false)
{
    // FIXME: This leaks.
    // FIXME: Might not be TLS?
    if (!glob_ctx)
        glob_ctx = SSL_CTX_new(TLSv1_method()) ;
    if (!glob_ctx) {
        SSL_load_error_strings() ;
        ERR_load_crypto_strings() ;
        ERR_print_errors_fp(stdout) ;
    }
}

ssl_processor::ssl_buff::~ssl_buff()
{
    if (m_ssl) SSL_free(m_ssl) ;
}

int ssl_processor::ssl_buff::get_len(const uint8_t *ptr, size_t len)
{
    if (len<5) return 0 ;
    if (m_initial)
    {
        // Free-wheeling until we see a likely message. This is to skip HTTP CONNECT etc.
        if (0x80==ptr[0] && 0x01==ptr[2] && 0x03==ptr[3] && ptr[4]<3)
        {
            // SSL 2.0 client hello : FIXME: This is very approximate
            m_initial = false ;
            return 2+ptr[1] ;
        }
        if (ptr[0]<0x14 || ptr[0]>0x17 || ptr[1]!=0x03)
            return len ;  // Skip. Doesn't look good (yet)
        m_initial = false ;
    }
    return 5 + (ptr[3]<<8 | ptr[4]) ;
}

const uint8_t *ssl_processor::ssl_buff::next(size_t &len)
{
    const uint8_t *rv = buffer::next(len) ;
    return m_initial?0:rv ;
}

void ssl_processor::ssl_buff::setup_crypt(uint8_t *dec, int keylen, common &com, int use_state)
{
    int rv ;
    if ( (!com.got_cli) || (!com.got_srv) ) return ;
    m_ssl        = SSL_new(glob_ctx) ;
    if (!m_ssl) return ;
    m_ssl->session = SSL_SESSION_new() ;
    if (!m_ssl->session) return ;
    memcpy(m_ssl->s3->client_random, com.cli_rand, SSL3_RANDOM_SIZE) ;
    memcpy(m_ssl->s3->server_random, com.srv_rand, SSL3_RANDOM_SIZE) ;
    m_ssl->s3->tmp.new_cipher = m_ssl->method->get_cipher_by_char(com.cipher) ;
    if (!m_ssl->s3->tmp.new_cipher) return ;
    ssl3_init_finished_mac(m_ssl) ;
    ssl3_finish_mac(m_ssl, (const unsigned char *)"dummy", 5) ; // FIXME: This is a hack!!
    if (dec)
    {
        // We have decrypted pre master
        rv = m_ssl->method->ssl3_enc->generate_master_secret(m_ssl,
                                                             m_ssl->session->master_key,
                                                             dec,
                                                             keylen) ;
        if (rv <= 0) return ;
        m_ssl->session->master_key_length = rv ;
        if (com.got_sess_id && SSL_ST_ACCEPT==use_state)
            // Have session-ID - Cache master secret for later use
            g_cache.add(com.sess_id, m_ssl->session->master_key, rv) ;
    }
    else if (com.got_sess_id) {
        // No pre master - do we have a cached master for the session-ID?
        uint8_t *mk ;
        rv = g_cache.find(com.sess_id, &mk) ;
        if (!rv) return ;
        memcpy(m_ssl->session->master_key, mk, rv) ;
        m_ssl->session->master_key_length = rv ;
    } else
        // No way to decryp. Fail.
        return ;
    m_ssl->state = use_state ;
    m_ssl->s3->change_cipher_spec = 1 ;
    if (!ssl3_do_change_cipher_spec(m_ssl)) return ;
    m_can_decrypt = true ;
}

size_t ssl_processor::ssl_buff::decrypt(const uint8_t *in, uint8_t *out, size_t len)
{
    int rv, ii ;
    int mac_size ;
    SSL3_RECORD *rec ;
    uint8_t md[EVP_MAX_MD_SIZE] ;

    if ( (!m_can_decrypt) || (len<6)) return -1 ;
    memcpy(out,in+5,len-5) ;

    m_ssl->s3->rrec.type   = in[0] ;
    m_ssl->s3->rrec.input  = (uint8_t *)in+5 ;
    m_ssl->s3->rrec.data   = out ;
    m_ssl->s3->rrec.length = len-5 ;

    // Decrypt
    rv = m_ssl->method->ssl3_enc->enc(m_ssl, 0) ; //0=decrypt
    if (rv <= 0) return -1 ;

    // Check the MAC
    mac_size = EVP_MD_CTX_size(m_ssl->read_hash) ;
    if ( (mac_size <= 0) || (m_ssl->s3->rrec.length < mac_size) )
        return -1 ;

    m_ssl->s3->rrec.length -= mac_size ;
    m_ssl->s3->rrec.input   = out ;
    rv = m_ssl->method->ssl3_enc->mac(m_ssl, md, 0) ;
    if ( (rv != mac_size) || memcmp(md, out+m_ssl->s3->rrec.length, mac_size) )
        return -1 ;

    // All OK.
    return m_ssl->s3->rrec.length ;
}

ssl_processor::parseHS::parseHS(const uint8_t *p, size_t len) :
        m_ptr(p), m_len(len)
{
}

const uint8_t *ssl_processor::parseHS::next(uint8_t &type, size_t &len)
{
    const uint8_t *rv ;
    if (0==m_len) return 0 ;
    if (m_len < 4) throw std::runtime_error("Bad SSL Handshake") ;
    type = m_ptr[0] ;
    len  = m_ptr[1]<<16 | m_ptr[2]<<8 | m_ptr[3] ;
    if (m_len < (4+len)) throw std::runtime_error("Bad SSL Handshake") ;
    rv     = m_ptr+4 ;
    m_ptr += 4+len ;
    m_len -= 4+len ;
    return rv ;
}

const char *ssl_processor::parse_cert(const uint8_t *p, size_t plen)
{
    BIGNUM *n, *e ;
    if (!read_cert(p,plen,&n,&e)) return "read_cert failed - bad CERT?" ;
    if (m_keyring && !m_common.priv)
    {
        m_common.priv = m_keyring->find(*n,*e) ;
        if (m_common.priv) printf("SSL private key found.\n") ;
    }
    BN_free(n) ;
    BN_free(e) ;
    return 0 ;
}

const char *ssl_processor::parse_certs(const uint8_t *p, size_t plen)
{
    const uint8_t *max = p + plen ;
    const char *rv ;
    size_t clen ;
    if (plen<6) return "parse_certs: invalid certs length" ;
    if ( plen != (3+(p[0]<<16|p[1]<<8|p[2]))) return "parse_certs: inconsistent lengths" ;
    p    += 3 ;
    if (p < max)
    {
        if ((max-p) < 4) return "parse_certs: cert parse error" ;
        clen = p[0]<<16 | p[1]<<8 | p[2] ;
        p   += 3 ;
        if ((max-p) < clen) return "parse_certs: Bad cert length" ;
        rv = parse_cert(p,clen) ;
        if (rv) return rv ;
    }
    if (!m_common.priv) return "No matching private key found" ;
    return 0 ;
}

const char *ssl_processor::parse(const uint8_t *p, size_t plen, bool is_client)
{
    const char *rv = 0 ;
    switch(p[0])
    {
    case 0x14: // ChangeCipherSpec
        if (!m_cli.m_can_decrypt && m_common.got_sess_id) {
            // Crypt not set, but we have session-id. Try resume.
            m_cli.setup_crypt(0,0,m_common,SSL_ST_ACCEPT) ;
            m_srv.setup_crypt(0,0,m_common,SSL_ST_CONNECT) ;
        }
        if (is_client)
            m_cli_crypt = true ;
        else
            m_srv_crypt = true ;
        break ;
    case 0x15: // Alert
        break ;
    case 0x16: // HS
        {
            uint8_t hs_type ;
            size_t  hs_len ;
            const uint8_t *hs_ptr ;
            parseHS MyHS(p+5,plen-5) ;
            while (0!=(hs_ptr=MyHS.next(hs_type,hs_len)))
            {
                switch(hs_type)
                {
                case 1: // Client Hello
                    if (!is_client) return "client_hello from SERVER!" ;
                    if (hs_len < (2+SSL3_RANDOM_SIZE)) return "Bad client_hello" ;
                    m_common.set_cli(hs_ptr+2) ;
                    break ;
                case 2: // Server Hello
                    if (is_client) return "server_hello from CLIENT!" ;
                    if (hs_len < (2+SSL3_RANDOM_SIZE+1)) return "Bad server_hello" ;
                    if (hs_len < (2+SSL3_RANDOM_SIZE+1+hs_ptr[2+SSL3_RANDOM_SIZE]+2)) return "Bad server_hello" ;
                    if (SSL3_SESSION_ID_SIZE == hs_ptr[2+SSL3_RANDOM_SIZE])
                        // Pick up session-id from server
                        m_common.set_sess(hs_ptr+2+SSL3_RANDOM_SIZE+1) ;
                    m_common.set_srv(hs_ptr+2,hs_ptr+2+SSL3_RANDOM_SIZE+1+hs_ptr[2+SSL3_RANDOM_SIZE]) ;
                    break ;
                case 11: // Cert
                    if (is_client) return "Unexpected CERT from client" ;
                    rv = parse_certs(hs_ptr, hs_len) ;
                    if (rv) return rv ;
                    break ;
                case 16: // Client Key Exchange
                    if (!is_client) return "Client key exchange from SERVER!" ;
                    if (hs_len < 3) return "Bad client key exchange" ;
                    if (m_common.priv)
                    {
                        uint8_t dec[m_common.priv->out_size()] ;
                        int keylen = m_common.priv->decrypt(dec, hs_ptr+2, hs_len-2) ;
                        if (keylen <= 0) return "RSA private key decrypt failed" ;
                        m_cli.setup_crypt(dec,keylen,m_common,SSL_ST_ACCEPT) ;
                        m_srv.setup_crypt(dec,keylen,m_common,SSL_ST_CONNECT) ;
                    }
                    break ;
                default:
                    break ;
                }
            }
        }
        break ;
    case 0x17: // AppData - should not be here if decrypting!
        return "No decryption was possible" ;
    case 0x80:
        // SSL 2.0 Client Hello?
        if (!is_client) return "SSLv2.0 ClientHello from SERVER!" ;
        if (!parse_2_hello(p,plen,m_common.cli_rand)) return "Failed to process SSLv2.0 ClientHello" ;
        m_common.got_cli = true ;
        break ;
    default:
        return "Unrecognised message type" ;
    }
    return 0 ;
}

ssl_processor::ssl_processor(processor &out) :
        m_cli_crypt(false),
        m_srv_crypt(false),
        m_error(false),
        m_err_msg(0),
        m_keyring(0),
        m_out(out)
{
}

ssl_processor::~ssl_processor()
{
}

bool ssl_processor::client(const uint8_t *data, size_t len)
{
    size_t plen ;
    const uint8_t *p ;
    if (m_error) return false ;
    if (!m_cli.add(data,len))
        m_error = true ;
    else
        while ( 0 != (p=m_cli.next(plen)) )
        {
            if (m_cli_crypt)
            {
                uint8_t out[plen] ;
                size_t olen = m_cli.decrypt(p, out, plen) ;
                if (-1 == (int)olen)
                {
                    m_error = true ;
printf("SSL: Decrypt failed\n") ;
                    return false ;
                }
                if (0x17 == p[0])
                    m_out.client(out,olen) ;
            }
            else
            {
                m_err_msg = parse(p,plen,true) ;
                if (m_err_msg)
                {
printf("SSL-ERROR: %s\n", m_err_msg) ;
                    m_error = true ;
                    return false ;
                }
            }
        }
    return true ;
}

bool ssl_processor::server(const uint8_t *data, size_t len)
{
    size_t plen ;
    const uint8_t *p ;
    if (m_error) return false ;
    if (!m_srv.add(data,len))
        m_error = true ;
    else
        while ( 0 != (p=m_srv.next(plen)) )
        {
            if (m_srv_crypt)
            {
                uint8_t out[plen] ;
                size_t olen = m_srv.decrypt(p, out, plen) ;
                if (-1 == (int)olen)
                {
                    m_error = true ;
printf("SSL: Decrypt failed\n") ;
                    return false ;
                }
                if (0x17 == p[0])
                    m_out.server(out,olen) ;
            }
            else
            {
                m_err_msg = parse(p,plen,false) ;
                if (m_err_msg)
                {
printf("SSL-ERROR: %s\n", m_err_msg) ;
                    m_error = true ;
                    return false ;
                }
            }
        }
    return true ;
}

void ssl_processor::set_keyring(const keyring *kr)
{
    m_keyring = kr ;
}

bool ssl_processor::error() const
{
    return m_error ;
}
