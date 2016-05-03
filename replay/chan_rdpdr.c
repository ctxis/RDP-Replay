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
#include <stdio.h>


#define RDPDR_CTYP_CORE                 0x4472 /* Device redirector core component; most of the packets in this protocol are sent under this component ID. */
#define RDPDR_CTYP_PRN                  0x5052 /* Printing component. The packets that use this ID are typically about printer cache management and identifying XPS printers. */

#define PAKID_CORE_CLIENTID_CONFIRM     0x4343 /* Client Announce Reply and Server Client ID Confirm, as specified in sections 2.2.2.3 and 2.2.2.6. */
#define PAKID_CORE_CLIENT_NAME          0x434E /* Client Name Request, as specified in section 2.2.2.4. */
#define PAKID_CORE_CLIENT_CAPABILITY    0x4350 /* Client Core Capability Response, as specified in section 2.2.2.8. */
#define PAKID_CORE_DEVICELIST_ANNOUNCE  0x4441 /* Client Device List Announce Request, as specified in section 2.2.2.9. */
#define PAKID_CORE_DEVICELIST_REMOVE    0x444D /* Client Drive Device List Remove, as specified in section 2.2.3.2. */
#define PAKID_CORE_DEVICE_IOCOMPLETION  0x4943 /* Device I/O Response, as specified in section 2.2.1.5. */
#define PAKID_CORE_DEVICE_IOREQUEST     0x4952 /* Device I/O Request, as specified in section 2.2.1.4. */
#define PAKID_CORE_SERVER_ANNOUNCE      0x496E /* Server Announce Request, as specified in section 2.2.2.2. */
#define PAKID_CORE_SERVER_CAPABILITY    0x5350 /* Server Core Capability Request, as specified in section 2.2.2.7. */
#define PAKID_CORE_USER_LOGGEDON        0x554C /* Server User Logged On, as specified in section 2.2.2.5. */
#define PAKID_CORE_DEVICE_REPLY         0x6472 /* Server Device Announce Response, as specified in section 2.2.2.1. */

#define PAKID_PRN_CACHE_DATA            0x5043 /* Add Printer Cachedata, as specified in [MS-RDPEPC] section 2.2.2.3. */
#define PAKID_PRN_USING_XPS             0x5543 /* Server Printer Set XPS Mode, as specified in [MS-RDPEPC] section 2.2.2.2. */

#define GET2_LE(p) ((p)[0]|(p)[1]<<8)
#define GET4_LE(p) ((p)[0]|(p)[1]<<8|(p)[2]<<16|(p)[3]<<24)


void se_out(const char *msg, const uint8_t *p, const uint8_t *max) ;


/* Printer device info: http://msdn.microsoft.com/en-us/library/cc242137.aspx */
static void do_prn_dev_announce(uint8_t *p, uint8_t *max)
{
    if ((max-p) < 44) return ;
    uint32_t flags = GET4_LE(p+20) ;
    uint32_t code  = GET4_LE(p+24) ;
    uint32_t p_len = GET4_LE(p+28) ;
    uint32_t d_len = GET4_LE(p+32) ;
    uint32_t n_len = GET4_LE(p+36) ;
    uint32_t c_len = GET4_LE(p+40) ;
    if ((44+p_len+d_len+n_len+c_len) != (max-p)) return ;
    if (flags&2) printf(" (default)") ;
    if (n_len && 0==(1&n_len))
    {
        printf(" Name:") ;
        const uint8_t *pp = p+44+p_len+d_len ;
        uint32_t ii ;
        for (ii=0 ; ii<(n_len-2) ; ++ii)
        {
            if (ii&1) continue ;
            if ((31<pp[ii]) && (pp[ii]<127))
                putchar(pp[ii]) ;
            else
                putchar('.') ;
        }
    }
}


/* Server Announce: http://msdn.microsoft.com/en-us/library/cc241343.aspx */
static void do_DrIn(uint8_t *p, uint8_t *max, int is_up)
{
    if (12 != (max-p)) return ;
    printf("RDPDR: Server-Announce: Server v%u.%u client-id=%u\n",
           (unsigned)GET2_LE(p+4),
           (unsigned)GET2_LE(p+6),
           (unsigned)GET4_LE(p+8)) ;
}


/* Client Announce: http://msdn.microsoft.com/en-us/library/cc241344.aspx */
static void do_DrCC(uint8_t *p, uint8_t *max, int is_up)
{
    if (12 != (max-p)) return ;
    printf("RDPDR: Client-Announce: Client v%u.%u client-id=%u\n",
           (unsigned)GET2_LE(p+4),
           (unsigned)GET2_LE(p+6),
           (unsigned)GET4_LE(p+8)) ;
}


/* Client Name: http://msdn.microsoft.com/en-us/library/cc241345.aspx */
static void do_DrCN(uint8_t *p, uint8_t *max, int is_up)
{
    int unicode = GET4_LE(p+4) ;
    int name_ln = GET4_LE(p+12) ;
    int ii ;
    if (max == (p+16+name_ln))
    {
        printf("RDPDR: ClientName: ") ;
        p += 16 ;
        for (ii=0 ; ii<name_ln ; ++ii)
        {
            if (unicode && (ii&1)) continue ;
            if ( (31<p[ii]) && (p[ii]<127) ) putchar(p[ii]) ; else putchar('.') ;
        }
        putchar('\n') ;
    }
}


/* Server Core Capability: http://msdn.microsoft.com/en-us/library/cc241348.aspx */
static void do_DrSP(uint8_t *p, uint8_t *max, int is_up)
{
    se_out("RDPDR: Server Capability: ", p+4, max) ;
}


/* Client Core Capability: http://msdn.microsoft.com/en-us/library/cc241354.aspx */
static void do_DrCP(uint8_t *p, uint8_t *max, int is_up)
{
    se_out("RDPDR: Client Capability: ", p+4, max) ;
}


/* Server User Logged On: http://msdn.microsoft.com/en-gb/library/cc241346.aspx */
static void do_DrUL(uint8_t *p, uint8_t *max, int is_up)
{
    if (4 != (max-p)) return ;
    printf("RDPDR: User Logged On\n") ;
}


/* Device Announce: http://msdn.microsoft.com/en-gb/library/cc241355.aspx */
static void do_DrDA(uint8_t *p, uint8_t *max, int is_up)
{
#define RDPDR_DTYP_SERIAL       0x00000001 /* Serial port device */
#define RDPDR_DTYP_PARALLEL     0x00000002 /* Parallel port device */
#define RDPDR_DTYP_PRINT        0x00000004 /* Printer device */
#define RDPDR_DTYP_FILESYSTEM   0x00000008 /* File system device */
#define RDPDR_DTYP_SMARTCARD    0x00000020 /* Smart card device */
    p += 4 ;
    if ((max-p)<4) return ;
    uint32_t cnt = GET4_LE(p) ;
    uint32_t ii,jj ;
    p += 4 ;
    for (ii=0 ; ii<cnt ; ++ii)
    {
        if ((max-p) < 20) return ;
        uint32_t len = GET4_LE(p+16) ;
        if ((max-p) < (20+len)) return ;
        uint32_t type = GET4_LE(p) ;
        uint32_t id   = GET4_LE(p+4) ;
        const char *stype = "Unknown" ;
        switch(type)
        {
        case RDPDR_DTYP_SERIAL:         stype = "Serial" ; break ;
        case RDPDR_DTYP_PARALLEL:       stype = "Parallel" ; break ;
        case RDPDR_DTYP_PRINT:          stype = "Printer" ; break ;
        case RDPDR_DTYP_FILESYSTEM:     stype = "Filesystem" ; break ;
        case RDPDR_DTYP_SMARTCARD:      stype = "Smartcard" ; break ;
        }
        printf("RDPDR: Device-Announce: %s Dev-id=%u, name=", stype, (unsigned)id) ;
        for (jj=0 ; jj<8 ; ++jj)
        {
            if (0==p[8+jj]) break ;
            if ((31 < p[8+jj]) && (p[8+jj]<127))
                putchar(p[8+jj]) ;
            else
                putchar('.') ;
        }
        if (RDPDR_DTYP_PRINT == type)
            do_prn_dev_announce(p,p+20+len) ;
        putchar('\n') ;
        p += 20+len ;
    }
}


/* Client Drive Device List remove: http://msdn.microsoft.com/en-gb/library/cc241358.aspx */
static void do_DrDM(uint8_t *p, uint8_t *max, int is_up)
{
    printf("RDPDR: Devicelist Remove\n") ;
}


/* Device Announce Response: http://msdn.microsoft.com/en-gb/library/cc241342.aspx */
static void do_Drdr(uint8_t *p, uint8_t *max, int is_up)
{
    if (12 != (max-p)) return ;
    printf("RDPDR: Announce-Response: Dev-id=%u result=%u\n",
           (unsigned)GET4_LE(p+4),
           (unsigned)GET4_LE(p+8)) ;
}


/* Device I/O Request: http://msdn.microsoft.com/en-gb/library/cc241327.aspx */
static void do_DrIR(uint8_t *p, uint8_t *max, int is_up)
{
    if ((max-p)<24) return ;
    printf("RDPDR: I/O-Request: Dev-id=%u\n", (unsigned)GET4_LE(p+4)) ;
}


/* Device I/O Completion: http://msdn.microsoft.com/en-us/library/cc241372.aspx */
static void do_DrIC(uint8_t *p, uint8_t *max, int is_up)
{
    printf("RDPDR: I/O-Completion\n") ;
}


/* http://msdn.microsoft.com/en-gb/library/cc241324.aspx */
void replay_chan_rdpdr(uint8_t *p, uint8_t *max, int is_up)
{
    if ((max-p)<4) return ;
    uint16_t comp = p[0] | p[1]<<8 ;
    uint16_t pid  = p[2] | p[3]<<8 ;
    switch (comp)
    {
    case RDPDR_CTYP_CORE:
        switch (pid)
        {
        case PAKID_CORE_CLIENTID_CONFIRM:    do_DrCC(p,max,is_up) ; break ;
        case PAKID_CORE_CLIENT_NAME:         do_DrCN(p,max,is_up) ; break ;
        case PAKID_CORE_CLIENT_CAPABILITY:   do_DrCP(p,max,is_up) ; break ;
        case PAKID_CORE_DEVICELIST_ANNOUNCE: do_DrDA(p,max,is_up) ; break ;
        case PAKID_CORE_DEVICELIST_REMOVE:   do_DrDM(p,max,is_up) ; break ;
        case PAKID_CORE_DEVICE_IOCOMPLETION: do_DrIC(p,max,is_up) ; break ;
        case PAKID_CORE_DEVICE_IOREQUEST:    do_DrIR(p,max,is_up) ; break ;
        case PAKID_CORE_SERVER_ANNOUNCE:     do_DrIn(p,max,is_up) ; break ;
        case PAKID_CORE_SERVER_CAPABILITY:   do_DrSP(p,max,is_up) ; break ;
        case PAKID_CORE_USER_LOGGEDON:       do_DrUL(p,max,is_up) ; break ;
        case PAKID_CORE_DEVICE_REPLY:        do_Drdr(p,max,is_up) ; break ;
        default:
            printf("Unknown CORE message: %04x (%d bytes)\n", (unsigned)pid, (int)(max-p)) ;
            break ;
        }
        break ;
    case RDPDR_CTYP_PRN:
        switch (pid)
        {
        case PAKID_PRN_CACHE_DATA:
        case PAKID_PRN_USING_XPS:
            printf("Unprocessed PRN message: %04x (%d bytes)\n", (unsigned)pid, (int)(max-p)) ;
            break ;
        default:
            printf("Unknown PRN message: %04x (%d bytes)\n", (unsigned)pid, (int)(max-p)) ;
            break ;
        }
        break ;
    default:
        printf("Unknown type/message %04x/%04x (%d bytes)\n", (unsigned)comp, (unsigned)pid, (int)(max-p)) ;
        break ;
    }
}
