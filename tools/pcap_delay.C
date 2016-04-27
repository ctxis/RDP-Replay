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

#include "pcap_delay.h"

#include <poll.h>
#include <sys/time.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>


inline void pcap_delay::sleep(double s)
{
    if (s > 0.0) (void)poll(0, 0, (int)(s*1000)) ;
}


void pcap_delay::delay()
{
    struct timeval now ;
    float frt, fin, zzz ;

    while (m_pause) poll(0,0,100) ;

    // See if we are rate throttling
    if (m_rate <= 0) return ;

    if (gettimeofday(&now,0)) return ;

    // Set time base
    if (0 == m_off_rt)
    {
        m_off_rt = now.tv_sec ;
        m_off_in = m_tv.tv_sec ;
        if (now.tv_usec > m_tv.tv_usec) m_off_rt += 1 ;
    }

    // Up the base offsets, if needed
    if ((m_tv.tv_sec - m_off_in) > m_rate)
    {
        m_off_in += m_rate ;
        m_off_rt += 1 ;
    }

    frt = (now.tv_sec - m_off_rt) + (now.tv_usec/MS) ;
    fin = (m_tv.tv_sec - m_off_in) + (m_tv.tv_usec/MS) ;
    zzz = fin - (frt*m_rate) ;

    if (zzz > 0.0) sleep(zzz/m_rate) ;
}


void pcap_delay::show_time(bool show)
{
    m_show_time = show ;
    if (show) printf("\x1b[2J\x1b[1;1H\n\n\n") ;        
}


void pcap_delay::process(const struct pcap_pkthdr *h, const u_char *p)
{
    m_tv = h->ts ;
    if (m_show_time)
    {
        (void)gmtime_r(&h->ts.tv_sec, &m_tm) ;
        // VT-100 terminal control:
        //   Esc-[s         Save cursor
        //   Esc-[1;1H      Set cursor pos to 1,1 (top-left)
        //   Esc-[41;37m    White-On-Red
        //   Esc-[K         Kill to EOL
        //   Esc-[0m        Reset colours
        //   Esc-[u         Resore cursor
        printf("\x1b[s\x1b[1;1H\x1b[41;37m %04d:%02d:%02d %02d:%02d:%02d \x1b[K\n\x1b[0m\x1b[u",
               1900+m_tm.tm_year, m_tm.tm_mon, m_tm.tm_mday,
               m_tm.tm_hour, m_tm.tm_min, m_tm.tm_sec) ;
        fflush(stdout) ;
    }
    delay() ;
    m_out(m_user, h, p) ;
}


void pcap_delay::process(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
    pcap_delay *pd = reinterpret_cast<pcap_delay *>(user) ;
    pd->process(h,p) ;
}


pcap_delay::pcap_delay(void (*out)(u_char *, const struct pcap_pkthdr *, const u_char *),
                       u_char *user)
{
    m_user      = user ;
    m_out       = out ;
    m_show_time = false ;
    m_pause     = false ;
    m_off_rt    = 0 ;
    m_off_in    = 0 ;
    m_rate      = 1 ;
    memset(&m_tm, 0, sizeof(m_tm)) ;
}


extern "C"
{
}
