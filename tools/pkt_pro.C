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

#include "pkt_pro.h"
#include <stdlib.h>
#include <string.h>

class tcp_reseq
{
    struct tcp_blk
    {
        tcp_blk     *m_next ;
        tcp_blk     *m_prev ;
        uint32_t     m_seq ;
        uint32_t     m_end ;
        uint8_t      m_data[0] ;
    } ;

    struct side
    {
        uint32_t   m_next ;
        bool       m_first ;
        tcp_blk   *m_hold ;
        side() : m_first(true), m_hold(0) {}
        ~side()
        {
            while (m_hold)
            {
                tcp_blk *rm = m_hold ;
                m_hold = rm->m_next ;
                free(rm) ;
            }
        }
    } ;

    side        m_cli ;
    side        m_srv ;
    processor  &m_out ;

    void flush(side *ctx,
               PTR p,
               PTR max)
    {
        tcp_blk *ii, *next ;
        int done, tot ;
        int32_t off, end ;
        do
        {
            done = 0 ;
            tot  = 0 ;
            for (ii=ctx->m_hold ; ii ; ii=next)
            {
                ++tot ;
                next = ii->m_next ;
                off  = ii->m_seq - ctx->m_next ;
                if (off <= 0)
                {
                    end  = ii->m_end - ctx->m_next ;
                    if (end > 0)
                    {
                        // New data
                        PTR p   = ii->m_data ;
                        PTR max = ii->m_data + ii->m_end - ii->m_seq ;
                        if (off < 0) p -= off ;
                        if (&m_cli == ctx)
                            m_out.client(p, max-p) ;
                        else
                            m_out.server(p, max-p) ;
                        ctx->m_next = ii->m_end ;
                    }
                    // Either way this blk is no longer neeed
                    if (ii->m_prev)
                        ii->m_prev->m_next = ii->m_next ;
                    else
                        ctx->m_hold = ii->m_next ;
                    if (ii->m_next)
                        ii->m_next->m_prev = ii->m_prev ;
                    free(ii) ;
                    ++done ;
                }
            }
        } while (done>0) ;
        if (tot>=100) printf("%p: TCP-ERROR: Too many buffered data blocks!!!\n", this) ;
    }

    void buffer(side *ctx,
                uint32_t seq,
                PTR p,
                PTR max)
    {
        int len = (int)(max-p) ;
        tcp_blk *blk = (tcp_blk *)malloc(sizeof(tcp_blk)+len) ;
        if (!blk)
        {
            printf("ERROR: malloc() failed for length=%d\n", len) ;
            return ;
        }
        memcpy(blk->m_data,p,len) ;
        blk->m_seq  = seq ;
        blk->m_end  = seq+len ;
        blk->m_prev = 0 ;
        blk->m_next = ctx->m_hold ;
        if (ctx->m_hold)
            ctx->m_hold->m_prev = blk ;
        ctx->m_hold = blk ;
    }

    void process(side *ctx,
                 uint32_t seq,
                 PTR p,
                 PTR max)
    {
        int32_t off = (int32_t)(seq-ctx->m_next) ;
        int32_t end = (int32_t)(seq+(max-p)-ctx->m_next) ;
        if (off<0)
        {
            if (end<=0) return ; // No new data
            p   -= off ;
            seq -= off ;
            off  = 0 ;
        }
        if (off)
        {
            // We resequence here!
            buffer(ctx, seq, p, max) ;
        }
        else
        {
            if (&m_cli==ctx)
                m_out.client(p, max-p) ;
            else
                m_out.server(p, max-p) ;
            ctx->m_next = seq + (max-p) ;
            if (ctx->m_hold) flush(ctx,p,max) ;
        }
    }

public:

    tcp_reseq(processor &out) : m_out(out)
    {
    }

    inline void client(uint32_t seq, PTR p, size_t len)
    {
        process(&m_cli,seq,p,p+len) ;
    }

    inline void server(uint32_t seq, PTR p, size_t len)
    {
        process(&m_srv,seq,p,p+len) ;
    }
    void cli_syn(uint32_t seq) { m_cli.m_first = false ; m_cli.m_next = seq+1 ; }
    void srv_syn(uint32_t seq) { m_srv.m_first = false ; m_srv.m_next = seq+1 ; }
} ;


struct pkt_pro::foot
{
    foot      *m_next ;
    uint32_t   m_sip ;
    uint32_t   m_dip ;
    uint16_t   m_sport ;
    uint16_t   m_dport ;
    tcp_reseq *m_pro ;
    processor *m_keep ;
    foot(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) :
            m_next(0),
            m_sip(sip),
            m_dip(dip),
            m_sport(sport),
            m_dport(dport),
            m_pro(0),
            m_keep(0)
    {
    }
    bool operator==(const foot&r)
    {
        return r.m_sip   == m_sip   &&
                r.m_dip   == m_dip   &&
                r.m_sport == m_sport &&
                r.m_dport == m_dport ;
    }
} ;

pkt_pro::foot *pkt_pro::find_foot(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
    // foot needle(sip, dip, sport, dport) ;
    for (foot *ii=m_feet ; ii ; ii=ii->m_next)
        if ( ii->m_sip   == sip   &&
             ii->m_dip   == dip   &&
             ii->m_sport == sport &&
             ii->m_dport == dport)
            return ii ;
}

void pkt_pro::del_foot(foot *rm)
{
    foot *prev = 0 ;
    foot *ii ;
    for (ii=m_feet ; ii ; ii=ii->m_next)
        if (ii==rm)
            break ;
        else
            prev = ii ;
    if (ii)
    {
        if (prev) prev->m_next = ii->m_next ;
        else      m_feet       = ii->m_next ;
    }
    untake(ii->m_keep) ;
    delete ii->m_pro ;
    delete ii ;
}

pkt_pro::foot *pkt_pro::MaybeNewFoot(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp)
{
    foot *fp = find_foot(sip,dip,sp,dp) ;
    if (fp) del_foot(fp) ;
    fp = find_foot(dip,sip,dp,sp) ;
    if (fp) del_foot(fp) ;
    fp = 0 ;
    processor *pro = take(sip,dip,sp,dp) ;
    if (pro)
    {
        fp         = new foot(sip, dip, sp, dp) ;
        fp->m_pro  = new tcp_reseq(*pro) ;
        fp->m_keep = pro ;
        fp->m_next = m_feet ;
        m_feet     = fp ;
    }
    return fp ;
}

inline uint16_t pkt_pro::sum(PTR p, size_t len, uint32_t s)
{
    int ii, ll = len&~1 ;
    if (len&1) s += p[len-1]<<8 ;
    for (ii=0 ; ii<ll ; ii+=2)
        s += p[ii]<<8 | p[ii+1] ;
    while (s>0xffff)
        s = (0xffff&s) + (s>>16) ;
    return s ;
}

void pkt_pro::eth(PTR p, PTR max)
{
    if ( ((max-p) > 14) &&
         (0x08 == p[12]) &&
         (0x00 == p[13]) )
        ip4(p+14,max) ;
}

void pkt_pro::ip4(PTR p, PTR max)
{
    int hl, ipl ;
    uint32_t sip, dip ;
    if ( ((max-p) <= 20) ||
         (p[0]<0x45) ||
         (p[0]>0x4f) ||
         (p[9] != 0x06) )
        return ;
    // FIXME: Check IP checksum
    if ( (p[6]&0x3f) ||
         (p[7]) )
        return ; // FRAG: FIXME: Need to process frags?
    hl  = 0x3c&(p[0]<<2) ; // Header length
    ipl = p[2]<<8 | p[3] ; // IP length
    sip = p[12]<<24 | p[13]<<16 | p[14]<<8 | p[15] ;
    dip = p[16]<<24 | p[17]<<16 | p[18]<<8 | p[19] ;
    if ( (ipl > (max-p)) || (hl >= ipl) || (0xffff != sum(p,hl)) )
        return ;
    tcp(sip, dip, p+hl, p+ipl) ;
}

void pkt_pro::tcp(uint32_t sip, uint32_t dip, PTR p, PTR max)
{
    int hl ;
    uint32_t seq ;
    uint16_t sp, dp ;
    int dir = -1 ;

    // Quick length and header-length check
    if ( ((max-p) < 20) ||
         ((p[12]&0xf0) < 0x50) )
        return ;

    // Extract info
    hl  = 0x3c & (p[12]>>2) ;
    sp  = p[0]<<8  | p[1] ;
    dp  = p[2]<<8  | p[3] ;
    seq = p[4]<<24 | p[5]<<16 | p[6]<<8 | p[7] ;

    // Sanity check header length again
    if ( (max-p) < hl)
        return ;

    // Check the cksum
    if (m_sum && (0xffff != sum(p,(max-p), 6 + (sip&0xffff) + (dip&0xffff) + (sip>>16) + (dip>>16) + (max-p))))
        return ;

    foot *fp = 0 ;
    if ( (p[13]&0x3f) == 0x12)
    {
        // We look at SYN+ACK to ignore unanswered SYNs
        dir = 1 ;
        fp  = MaybeNewFoot(dip, sip, dp, sp) ;
        if (fp)
        {
            // Initialise the sequence numbers
            uint32_t ack = p[8]<<24 | p[9]<<16 | p[10]<<8 | p[11] ;
            fp->m_pro->srv_syn(seq) ;
            fp->m_pro->cli_syn(ack-1) ;
        }
    }
    else
    {
        dir = 1 ;
        fp  = find_foot(sip,dip,sp,dp) ;
        if (fp) dir = 0 ;
        else    fp  = find_foot(dip,sip,dp,sp) ;
    }

    // Check we want this packet
    if (!fp) return ;

    // Check for done.
    if (p[13]&0x05) // RST/FIN
    {
        del_foot(fp) ;
        return ;
    }

    // Skip the header
    p += hl ;
    if (max<=p) return ;

    // Looks good - process this
    if (0==dir)
        fp->m_pro->client(seq,p,max-p) ;
    else
        fp->m_pro->server(seq,p,max-p) ;
}
