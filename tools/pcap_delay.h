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

#ifndef PCAP_DELAY_H
#define PCAP_DELAY_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#if defined __cplusplus
class pcap_delay
{
    static const double MS = 1000000.0 ;

    int            m_rate ;
    bool           m_show_time ;
    bool           m_pause ;
    time_t         m_off_rt ;
    time_t         m_off_in ;
    struct tm      m_tm ;
    struct timeval m_tv ;
    u_char        *m_user ;
    void         (*m_out)(u_char *, const struct pcap_pkthdr *, const u_char *) ;

    static inline void sleep(double s) ;
    void delay() ;
    void process(const struct pcap_pkthdr *h, const u_char *p) ;

public:

    static void process(u_char *user, const struct pcap_pkthdr *h, const u_char *p) ;

    pcap_delay(void (*out)(u_char *, const struct pcap_pkthdr *, const u_char *),
               u_char *user=0) ;

    void show_time(bool show) ;

    inline void set_user(u_char *user)   { m_user      = user ; }
    inline void toggle()                 { m_pause     = !m_pause ; }
    inline void pause()                  { m_pause     = true ; }
    inline void go()                     { m_pause     = false ; m_off_rt = 0 ; }
    inline void rate(int r)              { m_rate      = r ; }
    inline int  rate() const             { return      m_rate ; }
    inline void fullspeed()              { m_rate      = 0 ; }
    inline void realtime()               { m_rate      = 1 ; }
    inline bool show_time()              { return m_show_time ; }
    const struct tm &get_tm() const      { return m_tm ; }
    const struct timeval &get_tv() const { return m_tv ; }
} ;

extern "C"
{
#endif

/* C interface */

#if defined __cplusplus
}
#endif

#endif
