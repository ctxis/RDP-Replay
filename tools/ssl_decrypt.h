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

#ifndef _SSL_DECRYPT_H
#define _SSL_DECRYPT_H

#include <stdint.h>
#include <openssl/ssl.h>

#include <buffer.h>
#include <processor.h>

#if defined __cplusplus


//! RSA private key
class RsaPriv
{
    RSA *m_key ;
public:
    /** \brief          Constructor needs the RSA key filename
     *  \param  filename  Name of the RSA key (PEM) file
     *  \note           This will throw an exception if there is a processing failure
     */
    RsaPriv(const char *filename) ;
    ~RsaPriv() ;
    /** \brief          Check the public modulus and exponent to see if they match this key
     *  \param  n       Modulus to check
     *  \param  e       Exponent to ckeck
     *  \return true    They match
     *  \return false   They do not match
     */
    bool check_pub(const BIGNUM &n, const BIGNUM &e) const ;
    /** \brief          Check the public key to see if they match this key
     *  \param  pub     Pointer to the public key to ckeck
     *  \param  len     Length of the public key
     *  \return true    They match
     *  \return false   They do not match
     */
    bool check_pub(const uint8_t *pub, size_t len) const ;
    /** \brief          Return the needed output buffer size
     *  \returns        The number of bytes needed in the output decrypt buffer
     *  \sa             decrypt
     */
    size_t out_size() const ;
    /** \brief          Decrypt using the private key
     *  \param  out     Output buffer (must be at least \ref out_size bytes long
     *  \param  in      Pointer to the input (encrypted) data
     *  \param  len     Length of the encrypted data (in bytes)
     *  \returns        The number of bytes of decrypt (0 for error)
     *  \sa             out_size
     */
    int decrypt(uint8_t *out, const uint8_t *in, size_t len) const ;
} ;


//! Manage RSA private keys.
class keyring
{
    struct RSA_key ;
    RSA_key *m_keys ;
public:
    keyring() ;
    ~keyring() ;
    /** \brief Add a key file to the ring.
     * \param  name    Name of the RSA key (PEM) file to add.
     * \return false   Failure
     * \return true    Success
     */
    bool add(const char *name) ;
    /** \brief Find the RSA private key from the public mudulus and exponents
     * \param  n    Modulus
     * \param  e    Exponent
     * \return 0    Failed to find the corresponding private key
     */
    const RsaPriv * find(const BIGNUM &n, const BIGNUM &e) const ;
    /** \brief Find the RSA private key from the public key
     * \param  pub  Pointer to the public key (ASN.1 BER format, usually from CERT)
     * \param  len  Length of the public key (in bytes)
     * \return 0    Failed to find the corresponding private key
     */
    const RsaPriv * find(const uint8_t *pub, size_t len) const ;
} ;


//! The SSL processor
class ssl_processor : public processor
{
    //! Holding space for common crypt information
    struct common
    {
        const RsaPriv *priv ;
        uint8_t  cli_rand[SSL3_RANDOM_SIZE] ;
        uint8_t  srv_rand[SSL3_RANDOM_SIZE] ;
        uint8_t  sess_id [SSL3_SESSION_ID_SIZE] ;
        uint8_t  cipher[2] ;
        bool     got_cli ;
        bool     got_srv ;
        bool     got_sess_id ;
        common() ;
        void set_cli(const uint8_t *cli) ;
        void set_srv(const uint8_t *srv, const uint8_t *cs) ;
        void set_sess(const uint8_t *id) ;
    } ;

    //! Data buffering, crypt settings and processing
    struct ssl_buff : public buffer
    {
        SSL           *m_ssl ;
        bool           m_initial ;
        bool           m_can_decrypt ;
        ssl_buff() ;
        ~ssl_buff() ;
        virtual int get_len(const uint8_t *ptr, size_t len) ;
        const uint8_t *next(size_t &len) ;
        void setup_crypt(uint8_t *dec, int keylen, common &com, int use_state) ;
        size_t decrypt(const uint8_t *in, uint8_t *out, size_t len) ;
    } ;

    //! Helper class for handshake parsing
    class parseHS
    {
        const uint8_t *m_ptr ;
        size_t         m_len ;
    public:
        parseHS(const uint8_t *p, size_t len) ;
        const uint8_t *next(uint8_t &type, size_t &len) ;
    } ;

    bool            m_cli_crypt ;
    bool            m_srv_crypt ;
    bool            m_error ;
    const char     *m_err_msg ;
    ssl_buff        m_cli ;
    ssl_buff        m_srv ;
    const keyring  *m_keyring ;
    processor      &m_out ; // Decrypt is sent here
    common          m_common ;

    const char *parse_cert(const uint8_t *p, size_t plen) ;
    const char *parse_certs(const uint8_t *p, size_t plen) ;
    const char *parse(const uint8_t *p, size_t plen, bool is_client) ;

public:

    /** \brief          Constructor: Needs an output processor
     *  \param  out     The output processor. Decrypted data will be sent here.
     */
    ssl_processor(processor &out) ;

    virtual ~ssl_processor() ;

    /** \brief Process data from the client
     *  \sa processor::client
     */
    virtual bool client(const uint8_t *data, size_t len) ;

    /** \brief Process data from the server
     *  \sa processor::server
     */
    virtual bool server(const uint8_t *data, size_t len) ;

    /** \brief          Set a keyring to use for RSA handshake processing.
     *  \param kr       The keyring to use.
     *  \sa             keyring
     */
    void set_keyring(const keyring *kr) ;

    /** \brief          Check for processing error
     *  \return true    There is a problem
     *  \return false    No error detected so far
     */
    bool error() const ;

    /** \brief          Return a description of the error
     *  \returns        The error message
     */
    const char *err_msg() const { return m_err_msg ; }
} ;

extern "C" {
#endif

/* C interface */

/** \brief Create a keyring to hold RSA private keys.
 *
 * This will create a keyring for use with SSL processing.
 * You will need to \link keyring_add add RSA keys \endlink (PEM files) to the ring before
 * it will be useful.
 * \return 0        On failure
 * \sa              keyring_add keyring_free
 */
void *keyring_create() ;

/** \brief Add a key to a keyring
 *
 * \param  kr       The keyring (see \ref keyring_create)
 * \param  filename Name of the RSA key (PEM) file to add.
 * \return 0        Failure
 * \return 1        Success
 * \sa              keyring_create keyring_free
 */
int keyring_add(void *kr, const char *filename) ;

/** \brief Free a keyring.
 *
 * The keyring \b must \b not be in use (e.g. by SSL processing)
 *
 * \param kr        The keyring (returned from \ref keyring_create)
 */
void keyring_free(void *kr) ;

/** \brief Create an SSL processor
 *
 * \param  client   The function to process decrypted client data
 * \param  server   The function to process decrypted server data
 * \param  kr       The keyring to use (returned from \ref keyring_create)
 * \return 0        On failure
 * \sa              keyring_create ssl_proc_client ssl_proc_server
 */
void *ssl_proc_create(void (*client)(void *, const uint8_t *, size_t),
                      void (*server)(void *, const uint8_t *, size_t),
                      void *kr) ;

/** \brief Process SSL data from the client.
 *
 * \param ssl       The ssl processor (returned from \ref ssl_proc_create)
 * \param data      Pointer to the data
 * \param len       Length of the data in bytes
 * \return  0       Processing failed
 * \return  1       Processing successful
 */
int ssl_proc_client(void *ssl, const uint8_t *data, size_t len) ;

/** Set the user data for the SSL processor
 *
 * \param ssl       The ssl processor (returned from \ref ssl_proc_create)
 * \param ud        User data for this processor.
 */
void ssl_set_user(void *vssl, void *ud) ;

/** \brief Process SSL data from the server.
 *
 * \param ssl       The ssl processor (returned from \ref ssl_proc_create)
 * \param data      Pointer to the data
 * \param len       Length of the data in bytes
 * \return  0       Processing failed
 * \return  1       Processing successful
 */
int ssl_proc_server(void *ssl, const uint8_t *data, size_t len) ;

/** \brief Check the status of the SSL processor
 *
 * \param ssl       The ssl processor (returned from \ref ssl_proc_create)
 * \return 0        All is well
 * \return 1        The processor is in an error state, and will not process any more data.
 */
int ssl_proc_ok(void *ssl) ;

/** \brief Free an SSL processor
 *
 * \param ssl       The ssl processor (returned from \ref ssl_proc_create)
 */
void ssl_proc_free(void *ssl) ;

#ifdef __cplusplus
}
#endif

#endif
