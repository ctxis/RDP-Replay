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

#include "buffer.h"
#include <string.h>


buffer::buffer(): m_got(0), m_space(0), m_mem(0), m_cur(0), m_error(false)
{
}


buffer::~buffer()
{
    if (m_mem) free(m_mem) ;
}


// Add data to the buffer
bool buffer::add(const uint8_t * ptr, size_t len)
{
    if (m_error) return false ;
    if (m_got)
    {
        if (m_space < (m_got+len))
        {
            uint8_t *newp = (uint8_t *)realloc(m_mem, m_got+len+SLACK) ;
            if (!newp)
            {
                m_error = true ;
                return false ;
            }
            m_mem   = newp ;
            m_space = m_got + len + SLACK ;
        }
        memcpy(m_mem+m_got, ptr, len) ;
        m_got += len ;
        m_cur  = m_mem ;
    }
    else
    {
        m_cur = ptr ;
        m_got = len ;
    }
    return true ;
}


// Get the next payload
const uint8_t *buffer::next(size_t &len)
{
    if (m_error) return 0 ;
    int need = get_len(m_cur, m_got) ;
    if (need<0)
    {
        m_error = true ;
        return 0 ;
    }
    if (need && need <= m_got)
    {
        // Full message. Process it.
        const uint8_t *rv = m_cur ;
        m_cur += need ;
        m_got -= need ;
        len    = need ;
        return rv ;
    }
    // Not enough for a message - might need to buffer
    if (m_got)
    {
        // We have data. Keep it tidy
        if (m_mem)
        {
            if (m_cur == m_mem) {
                // Already at the start - nothing to do
            } else if ((m_cur > m_mem) && m_cur<(m_mem+m_space)) {
                // In buffer higher up - move to beginning of buffer
                memmove(m_mem, m_cur, m_got) ;
            } else {
                // Need to copy to buffer
                if (m_got > m_space)
                {
                    // Need more memory
                    uint8_t *ptr = (uint8_t *)realloc(m_mem, m_got+SLACK) ;
                    if (!ptr)
                    {
                        m_error = true ;
                        return 0 ;
                    }
                    m_mem   = ptr ;
                    m_space = m_got + SLACK ;
                }
                memcpy(m_mem, m_cur, m_got) ;
            }
        }
        else
        {
            // Need to malloc space
            uint8_t *ptr = (uint8_t *)malloc(m_got+SLACK) ;
            if (!ptr)
            {
                m_error = true ;
                return 0 ;
            }
            m_mem   = ptr ;
            m_space = m_got + SLACK ;
            memcpy(m_mem, m_cur, m_got) ;
        }
    }
    return 0 ;
}



/*---------------------------------
 *   C interface support
 *--------------------------------*/


// For the C interface we need a simple class wrapper.
class c_buff : public buffer
{
    void *m_user ;
    int (*m_get_len)(void *, const uint8_t *ptr, size_t len) ;
public:
    c_buff(int (*f)(void *, const uint8_t *ptr, size_t len)) : m_get_len(f), m_user(0) {}
    virtual int get_len(const uint8_t *ptr, size_t len)
    {
        return m_get_len(m_user, ptr, len) ;
    }
    void set_user(void *u)
    {
        m_user = u ;
    }
} ;


extern "C" {


void *buffer_new(int (*get_len)(void *, const uint8_t *ptr, size_t len))
{
    return new c_buff(get_len) ;
}


void buffer_del(void *buff)
{
    c_buff *cb = reinterpret_cast<c_buff *>(buff) ;
    delete cb ;
}

void buffer_set_user(void *buff, void *user)
{
    c_buff *cb = reinterpret_cast<c_buff *>(buff) ;
    cb->set_user(user) ;
}

int buffer_add(void *buff, const uint8_t *ptr, size_t len)
{
    c_buff *cb = reinterpret_cast<c_buff *>(buff) ;
    return cb->add(ptr, len) ;
}

const uint8_t *buffer_next(void *buff, size_t *len)
{
    c_buff *cb = reinterpret_cast<c_buff *>(buff) ;
    return cb->next(*len) ;
}

}
