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

#include <stdlib.h>
#include <stdio.h>

#include <freerdp/types.h>
#include "rdpsnd_main.h"


// Sound header: http://msdn.microsoft.com/en-us/library/cc240954.aspx
#define SNDC_CLOSE		0x01 // Close PDU
#define SNDC_WAVE		0x02 // WaveInfo PDU
#define SNDC_SETVOLUME		0x03 // Volume PDU
#define SNDC_SETPITCH		0x04 // Pitch PDU
#define SNDC_WAVECONFIRM	0x05 // Wave Confirm PDU
#define SNDC_TRAINING		0x06 // Training PDU or Training Confirm PDU
#define SNDC_FORMATS		0x07 // Server Audio Formats and Version PDU or Client Audio Formats and Version PDU
#define SNDC_CRYPTKEY		0x08 // Crypt Key PDU
#define SNDC_WAVEENCRYPT	0x09 // Wave Encrypt PDU
#define SNDC_UDPWAVE		0x0A // UDP Wave PDU
#define SNDC_UDPWAVELAST	0x0B // UDP Wave Last PDU
#define SNDC_QUALITYMODE	0x0C // Quality Mode PDU
#define SNDC_WAVE2		0x0D // Wave2 PDU

#define GET2_LE(p) ((p)[0]|(p)[1]<<8)
#define GET4_LE(p) ((p)[0]|(p)[1]<<8|(p)[2]<<16|(p)[3]<<24)


typedef struct SoundSupport
{
    int                 next_data ;
    int                 no_chans ;
    int                 current ;
    int                 latency ;
    u_char              buff[4] ;
    rdpsndFormat       *channels ;
    rdpsndDevicePlugin *plug ;
} SoundSupport ;


static void MyReg(rdpsndPlugin* rdpsnd, rdpsndDevicePlugin* device)
{
    SoundSupport *ss = (SoundSupport *)rdpsnd ;
    ss->plug = device ;
}


void *replay_snd_alloc()
{
    int FreeRDPRdpsndDeviceEntry(PFREERDP_RDPSND_DEVICE_ENTRY_POINTS) ;
    SoundSupport *ss = calloc(1, sizeof(SoundSupport)) ;
    FREERDP_RDPSND_DEVICE_ENTRY_POINTS ep ;
    ep.rdpsnd                = (rdpsndPlugin*)ss ;
    ep.pRegisterRdpsndDevice = MyReg ;
    ep.plugin_data           = 0 ;
    FreeRDPRdpsndDeviceEntry(&ep) ;
    ss->current = -1 ;
    ss->latency = 15 ;
    return ss ;
}


void replay_snd_free(void *vp)
{
    int ii ;
    SoundSupport *snd = (SoundSupport *)vp ;
    if (snd->channels) {
        for (ii=0 ; ii<snd->no_chans ; ++ii)
            if (snd->channels[ii].data)
                free(snd->channels[ii].data) ;
        free(snd->channels) ;
    }
    if (snd->plug && snd->plug->Free)
        snd->plug->Free(snd->plug) ;
    free(vp) ;
}


static void free_ch(rdpsndFormat *chans, int mx)
{
    int ii ;
    for (ii=0 ; ii<mx ; ++ii)
        if (chans[ii].data)
            free(chans[ii].data) ;
    free(chans) ;
}


static void ReadFormats(SoundSupport *snd, u_char *p, u_char *max)
{
    if (snd->channels) return ; // Already Done?!??
    if (GET2_LE(p+2)==(max-p-4))
    {
        p += 4 ;
        if ((max-p)<20) return ;
        int i,nf = GET2_LE(p+14) ;
        rdpsndFormat *chans = (rdpsndFormat *)calloc(nf, sizeof(rdpsndFormat)) ;
        if (!chans) return ;
        p += 20 ;
        for (i=0 ; i<nf ; ++i)
        {
            /* wFormatTag(2),nChannels(2),nSamplesPerSec(4),nAvgbytePerSec(4),nBlockAlign(20,wBitsPerSample(2),cbSize(2),data(cbSize) */
            if ((max-p)<18) { free_ch(chans,i) ; return ; } // FIXME: leaks and chan[].data
    //      printf("  fmt=%d/ch=%d/Samp=%d/Bps=%d/Align=%d/Size=%d\n", GET2_LE(p), GET2_LE(p+2),
    //             GET4_LE(p+4),
    //             GET4_LE(p+8),
    //             GET2_LE(p+12),
    //             GET2_LE(p+14)) ;
            chans[i].wFormatTag     = GET2_LE(p) ;
            chans[i].nChannels      = GET2_LE(p+2) ;
            chans[i].nSamplesPerSec = GET4_LE(p+4) ;
            chans[i].nBlockAlign    = GET2_LE(p+12) ;
            chans[i].wBitsPerSample = GET2_LE(p+14) ;
            chans[i].cbSize         = GET2_LE(p+16) ;
            if ((p+chans[i].cbSize) > max) { free_ch(chans,i) ; return ; }
            if (chans[i].cbSize) {
                chans[i].data = malloc(chans[i].cbSize) ;
                if (chans[i].data) memcpy(p+18, chans[i].data, chans[i].cbSize) ;
            }
            p += 18+chans[i].cbSize ;
        }
        snd->channels = chans ;
        snd->no_chans = nf ;
        snd->current  = -1 ;
    }
}


static void DataBlock(SoundSupport *snd, u_char *p, u_char *max)
{
    // We are expecting data - just send it
    if ((max-p) != snd->next_data)
        printf("WARNING: Sound-Data: Expect %d got %d\n", snd->next_data, (int)(max-p)) ;
    memcpy(p, snd->buff, 4) ;
    if (snd->plug && snd->plug->Play)
        snd->plug->Play(snd->plug, p, max-p) ;
    snd->next_data = 0 ;
}


static void WaveData(SoundSupport *snd, u_char *p, u_char *max)
{
    int ind, size ;
    if ((max-p) != 16) return ;
    size = GET2_LE(p+2) ;
    ind  = GET2_LE(p+6) ;
    if (ind >= snd->no_chans) return ;
    if (size <= 8) return ;

    if ((snd->plug) && (snd->current != ind))
    {
        if (snd->current < 0)
        {
            if (snd->plug->Open)
            {
                snd->plug->Open(snd->plug, snd->channels+ind, snd->latency) ;
                snd->current = ind ;
            }
        }
        else
        {
            if (snd->plug->SetFormat)
            {
                snd->plug->SetFormat(snd->plug, snd->channels+ind, snd->latency) ;
                snd->current = ind ;
            }
        }
    }

    memcpy(snd->buff, p+12, 4) ;
    snd->next_data = size - 8 ;
}


static void SetVol(SoundSupport *snd, u_char *p, u_char *max)
{
    uint32 vol ;
    if ((max-p) != 8) return ;
    vol = GET4_LE(p+4) ;
    if (snd->plug && snd->plug->SetVolume)
        snd->plug->SetVolume(snd->plug, vol) ;
}


static void SndClose(SoundSupport *snd)
{
    // Send to indecats sound has (at the moment) stopped
    if (snd->plug && snd->plug->Start)
        snd->plug->Start(snd->plug) ;
}


void reply_snd_proc(void *vp, u_char *p, u_char *max, int is_up)
{
    SoundSupport *snd = (SoundSupport *)vp ;

    if (snd->next_data && !is_up) {
        DataBlock(snd,p,max) ;
        return ;
    }

    if ((max-p)>=4)
        switch (p[0])
        {
        case SNDC_CLOSE:
            if (!is_up) SndClose(snd) ;
            break ;
        case SNDC_WAVE:
            if (!is_up) WaveData(snd,p,max) ;
            break ;
        case SNDC_SETVOLUME:
            if (!is_up) SetVol(snd,p,max) ;
            break ;
        case SNDC_FORMATS:
            if (is_up) ReadFormats(snd,p,max) ;
            break ;
        default:
            break ;
        }
}
