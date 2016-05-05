#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <pcap.h>
#include <ssl_decrypt.h>
#include <buffer.h>
#include <pcap_delay.h>
#include <pkt_pro.h>

#include <readline/readline.h>
#include <readline/history.h>

extern "C" {
#include "librdp.h"
}


// Used to allow objects to control play speed
pcap_delay * glob_delay ;


void *monitor_thread(void *arg)
{
    extern int play_paused ;
    pthread_detach(pthread_self()) ;
    bool paused = false ;
    while (1)
    {
        poll(0,0,100) ;
        if      (paused && !play_paused) glob_delay->go() ;
        else if (play_paused && !paused) glob_delay->pause() ;
        paused = play_paused ;
    }
}


void help(int exv=0)
{
    printf("Usage: rdp_replay  <options>\n") ;
    printf("    -h                    Help. You're reading it!\n") ;
    printf("    -l <lsa_secrets_file> File containing LSA secrets for RDP decryption\n") ;
    printf("    -L <lsa_raw_secret>   File containing a single binary LSA secret\n") ;
    printf("    -o <output_file>      Output video file (e.g. \"rdp.avi\")\n") ;
    printf("    -p <rsa_priv_file>    PEM file with SSL key (can be repeated)\n") ;
    printf("    -r <pcap_file>        The pcap file (default is stdin)\n") ;
    printf("    -t <port>             The TCP port to select in the pcap (default: any)\n") ;
    printf("    -x <num>              Playback tcp stream at <num> times realtime\n") ;
    printf("    --clipboard_16le      Clipboard is assumed to be UTF16le and stripped back up 8-bit\n") ;
    printf("    --debug_chan          Show channel messages\n") ;
    printf("    --debug_caps          Show capabilities messages\n") ;
    printf("    --fullspeed           Playback tcp stream at full-speed\n") ;
    printf("    --help                Help. You're still reading it!\n") ;
    printf("    --no_cksum            Don't check the packet (IP and TCP) checksums\n") ;
    printf("    --no_cursor           Don't show the cursor\n") ;
    printf("    --realtime            Playback tcp stream in realtime\n") ;
    printf("    --reverse             Reverse client/server direction (sometimes useful for extracted data)\n") ;
    printf("    --save_clipboard      Save clipboard events to file (e.g. \"clip-00000000-up\")\n") ;
    printf("    --show_time           Display packet capture time\n") ;
    printf("    --show_keys           Display keypress (repeat for verbose)\n") ;
    printf("    --sound               Play sounds (experimental)\n") ;
    printf("    --rdprd               Display RDPDR channel requests\n") ;
    printf("    --sw                  Use SW_GDI for rendering (not recommended)\n") ;
    exit(exv) ;
}

// Set this to true for reverse TCP streams (used in RAT tunnelling etc.)
static bool g_reverse = false ;

int main(int argc, char *const *argv)
{
    pcap_t *ph ;
    const char *inf  = "-" ;
    int ret ;

    // This is our tcp stream processor
    struct MyPktPro : public pkt_pro
    {
        struct MyRDP : public processor
        {
            void *m_libh ;
            MyRDP()
            {
                m_libh = librdp_new() ;
            }
            ~MyRDP()
            {
                librdp_del(m_libh) ;
            }
            virtual bool client(const uint8_t *data, size_t len)
            {
                if (g_reverse) librdp_response(m_libh, data, len) ;
                else           librdp_request(m_libh, data, len) ;
                return true ;
            }
            virtual bool server(const uint8_t *data, size_t len)
            {
                if (g_reverse) librdp_request(m_libh, data, len) ;
                else           librdp_response(m_libh, data, len) ;
                return true ;
            }
        } ;
        bool      m_taking ;
        uint16_t  m_port ;
        int       m_rate ;
        MyRDP     m_rdp ;
        MyPktPro() : m_taking(false),m_port(0),m_rate(1) {}
        ~MyPktPro(){}
        void set_port(uint16_t p) { m_port = p ; }
        void rate(int r) { m_rate = r ; }
        virtual processor *take(uint32_t src_ip,
                                uint32_t dest_ip,
                                uint16_t src_port,
                                uint16_t dest_port)
        {
            if (m_taking) return 0 ; // One only! Please FIXME this
            if (m_port && m_port!=src_port && m_port!=dest_port) return 0 ;
            m_taking = true ;
            if (m_rate) glob_delay->rate(m_rate) ;
            else        glob_delay->fullspeed() ;
            librdp_set_ts(m_rdp.m_libh,&glob_delay->get_tv()) ;
            return &m_rdp ;
        }
        void untake(processor *p)
        {
//          delete p ;
        }
        static void my_process(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
        {
            pkt_pro *pro = reinterpret_cast<pkt_pro *>(user) ;
            pro->process(p, h->len) ;
        }
    } ;

    SSL_library_init() ;

    MyPktPro   one ;
    pcap_delay pdelay(MyPktPro::my_process, (u_char *)&one) ;

    glob_delay = &pdelay ;

    // We show the cursor by default
    librdp_show_cursor(one.m_rdp.m_libh,1) ;

    // Process args
    while (-1 != (ret=getopt(argc,argv,"hl:L:o:p:r:t:x:-:")))
        switch(ret)
        {
        case '-':
            if      (0==strcmp(optarg,"help"))           help() ;
            else if (0==strcmp(optarg,"fullspeed"))      one.rate(0) ;
            else if (0==strcmp(optarg,"realtime"))       one.rate(1) ;
            else if (0==strcmp(optarg,"reverse"))        g_reverse = true ;
            else if (0==strcmp(optarg,"show_time"))      pdelay.show_time(true) ;
            else if (0==strcmp(optarg,"show_keys"))      librdp_show_keys(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"sound"))          librdp_sound(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"rdpdr"))          librdp_rdpdr(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"debug_chan"))     librdp_debug_channels(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"debug_caps"))     librdp_debug_capabilities(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"debug_crypt"))    librdp_debug_crypt(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"debug_raw"))      librdp_debug_raw(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"save_clipboard")) librdp_save_clipboard(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"clipboard_16le")) librdp_clipboard_16le(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"sw"))             librdp_sw_gdi(one.m_rdp.m_libh) ;
            else if (0==strcmp(optarg,"no_cksum"))       one.do_cksum(false) ;
            else if (0==strcmp(optarg,"no_cursor"))      librdp_show_cursor(one.m_rdp.m_libh,0) ;
            else help(2) ;
            break ;
        case 'h':
            help() ;
            break ;
        case 'l':
            librdp_keys(optarg) ;
            break ;
        case 'L':
            librdp_key_raw(optarg) ;
            break ;
        case 'o':
            librdp_output(one.m_rdp.m_libh, optarg) ;
            break ;
        case 'p':
            librdp_sslkey(optarg) ;
            break ;
        case 'r':
            inf = optarg ;
            break ;
        case 't':
            one.set_port((uint16_t)atoi(optarg)) ;
            break ;
        case 'x':
            one.rate(atoi(optarg)) ;//pdelay.rate(atoi(optarg)) ;
            break ;
        default:
            help(2) ;
            break ;
        }

    ph = pcap_open_offline(inf, 0) ;
    if (!ph) help() ;

    pdelay.fullspeed() ; // Set pcap rate to fullspeed until we lock onto selected stream
    pthread_t th ;
    if (pthread_create(&th, 0, monitor_thread, 0))
    {
        printf("Sorry, pthread_create failed. Aborting.\n") ;
        exit(1) ;
    }

    (void)pcap_loop(ph, 0, pcap_delay::process, (u_char *)&pdelay) ;

    return 0 ;
}

