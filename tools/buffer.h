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

#ifndef _BUFFER_H
#define _BUFFER_H

#include <stdlib.h>
#include <stdint.h>

#if defined __cplusplus

/** \brief  Buffer base class.
 *  Provides buffering of data until a full payload is recieved.
 */
class buffer
{
    static const size_t SLACK = 1024 ;
    size_t         m_got ;
    size_t         m_space ;
    uint8_t       *m_mem ;
    const uint8_t *m_cur ;
    bool           m_error ;

public:

    buffer() ;
    ~buffer() ;

    /** \brief This defines the required packet/payload length
     *  You must implement this to provide the logic to parse the incomming data stream.
     *  \param   ptr      Pointer to the available data
     *  \param   len      Current data abailable at ptr, in bytes
     */
    virtual int get_len(const uint8_t *ptr, size_t len) = 0 ;

    /** \biref Add data to the buffer
     *  \param   ptr    data to add
     *  \param   len    Number of bytes of data to add
     *  \return  false Failure
     *  \return  true  Success
     */
    bool add(const uint8_t *ptr, size_t len) ;

    /** \brief Request the next payload.
     *  You \em MUST call this repeatedly until 0 is returned!
     *  \param len   Length of data to process
     *  \returns     Pointer to the data (or 0 if more input is required)
     */
    const uint8_t *next(size_t &len) ;
} ;

extern "C" {
#endif

/** \brief Create a new buffer
 *  \param get_len   Routine to be called to determine the payload length
 *  \returns         Handle for this buffer (or 0 on failure)
 */
void          *buffer_new(int (*get_len)(void *user, const uint8_t *ptr, size_t len)) ;

/** \brief Release the buffer previously allocated by \ref buffer_new
 *  \param buff    The buffer handle as returned by \ref buffer_new
 */
void           buffer_del(void *buff) ;

/** \brief Set the user information for the calls to get_len
 *  \param buff         Return from \link buffer_new \endlink
 *  \param user         The user data to use
 */
void           buffer_set_user(void *buff, void *user) ;

/** \brief Add data to the buffer
 *  \param buff    The buffer handle as returned by \ref buffer_new
 *  \param ptr     Pointer to the data
 *  \param len     Number of bytes of data to add
 *  \return  0     Failure
 *  \return  1     Success
 */
int            buffer_add(void *buff, const uint8_t *ptr, size_t len) ;

/** \brief Request the next packet/payload of data
 *  This must be called repeatedly after adding data.
 *  \param buff    The buffer handle as returned by \ref buffer_new
 *  \param len     Pointer to a variable to recieve the payload length
 *  \return        Pointer to the payload (or 0 if more input data is needed)
 */
const uint8_t *buffer_next(void *buff, size_t *len) ;

#if defined __cplusplus
}
#endif

#endif
