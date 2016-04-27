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

#include <stdint.h>
#include <processor.h>

typedef const uint8_t * PTR ;
class pkt_pro
{
    struct foot ;

    foot      *m_feet ;
    bool       m_sum ;

    foot *find_foot(uint32_t, uint32_t, uint16_t, uint16_t) ;

    void del_foot(foot *) ;

    foot *MaybeNewFoot(uint32_t, uint32_t, uint16_t, uint16_t) ;

    inline uint16_t sum(PTR, size_t, uint32_t s=0) ;

    void eth(PTR, PTR) ;

    void ip4(PTR, PTR) ;

    void tcp(uint32_t, uint32_t, PTR, PTR) ;

public:

    pkt_pro() : m_feet(0), m_sum(true) {}

    virtual ~pkt_pro()
    {
        release_all() ;
    }

    inline void release_all()
    {
        while (m_feet) del_foot(m_feet) ;
    }

    virtual processor *take(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port)
    {
        return 0 ;
    }

    virtual void untake(processor *p)
    {
    }

    void do_cksum(bool tf)
    {
        m_sum = tf ;
    }

    //! Data goes in here!
    void process(PTR p, size_t len)
    {
        eth(p, p+len) ;
    }
} ;
