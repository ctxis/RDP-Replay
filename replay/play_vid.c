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

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <X11/Xlib.h>

typedef struct
{
    AVFormatContext *ctx ;
    AVStream        *strm ;
    AVFrame         *pic ;
    uint8_t         *buff ;
    size_t           buff_len ;
} VidInfo ;


static void DelVid(VidInfo *vi)
{
    if (!vi) return ;
    if (vi->ctx)
    {
        if (vi->strm && vi->strm->codec)
        {
            av_write_trailer(vi->ctx) ;
            avcodec_close(vi->strm->codec) ;
        }
        if (vi->ctx->pb)
            avio_close(vi->ctx->pb) ;
        avformat_free_context(vi->ctx) ;
    }
    if (vi->pic)
    {
        if (vi->pic->data[0]) av_free(vi->pic->data[0]) ;
        av_free(vi->pic) ;
    }
    if (vi->buff) free(vi->buff) ;
    free(vi) ;
}


static const char *PopVid(VidInfo *vi, const char *filename, int width, int height)
{
    AVCodec  *codec ;
    int siz ;
    uint8_t *buf ;
    static const int RATE = 25 ;

    vi->ctx = avformat_alloc_context() ;
    if (!vi->ctx)
        return "Could not deduce output format" ;
    vi->ctx->oformat = av_guess_format(0,filename,0) ;
    if (!vi->ctx->oformat)
        return "Could not deduce output format" ;
    if (vi->ctx->oformat->video_codec == CODEC_ID_NONE)
        return "Not a video format" ;
    if (avio_open(&vi->ctx->pb, filename, AVIO_FLAG_WRITE))
        return "Failed to open output" ;
    codec = avcodec_find_encoder(vi->ctx->oformat->video_codec) ;
    if (!codec)
        return "Could not find video codec" ;
    vi->strm  = avformat_new_stream(vi->ctx, codec) ;
    if (!vi->strm)
        return "Could not create video stream" ;

    // Fill in ooperting parameters
    vi->strm->codec->pix_fmt        = PIX_FMT_YUV420P ;
    vi->strm->codec->flags          = 0 ;
    vi->strm->codec->bit_rate       = 500000 ;
    vi->strm->codec->width          = width ;
    vi->strm->codec->height         = height ;
    vi->strm->codec->time_base      = (AVRational){1,RATE} ;
    vi->strm->codec->gop_size       = RATE ; /* emit one intra frame every second */
    vi->strm->codec->max_b_frames   = 0 ;
    if (vi->ctx->oformat->flags & AVFMT_GLOBALHEADER)
        vi->strm->codec->flags |= CODEC_FLAG_GLOBAL_HEADER ;

    if (avcodec_open2(vi->strm->codec, codec, 0)<0) return "avcodec_open2 failed" ;

    // Frame
    vi->pic = avcodec_alloc_frame() ;
    if (!vi->pic)
        return "Could not allocate frame" ;
    siz = avpicture_get_size(vi->strm->codec->pix_fmt, width, height) ;
    buf = av_malloc(siz) ;
    if (!buf)
        return "Failed to allocate frame buffer" ;
    avpicture_fill((AVPicture*)vi->pic, buf, vi->strm->codec->pix_fmt, width, height) ;

    if (!(vi->ctx->oformat->flags & AVFMT_RAWPICTURE))
    {
        vi->buff_len = 2000000 ;
        vi->buff = malloc(vi->buff_len) ;
        if (!vi->buff) return "malloc(workspace) failed" ;
    }

    if (avformat_write_header(vi->ctx, 0))
        return "Failed to write headers" ;

    return 0 ;
}


static VidInfo *NewVid(const char *filename, int width, int height)
{
    static int need_init = 1 ;
    VidInfo *vi = calloc(1,sizeof(VidInfo)) ;
    const char *err ;
    if (need_init) {
        av_register_all() ;
        need_init = 0 ;
    }
    if (width&1) ++width ;
    if (height&1) ++height ;
    if (vi) {
        err = PopVid(vi,filename,width,height) ;
        if (!err) return vi ;
        printf("ERROR: %s\n", err) ;
        DelVid(vi) ;
    }
    return 0 ;
}


void *PlayVidAlloc(const char *fname, int width, int height)
{
    return NewVid(fname, width, height) ;
}


void PlayVidFree(void *vp)
{
    DelVid((VidInfo *)vp) ;
}


// Fill in the frame from the Ximage
static int Ximage2Pic(AVFrame *pic, const XImage *ximg, int width, int height)
{
    int x,y,off,F = ximg->bitmap_unit/8 ;
    uint8_t r,g,b ;

    /* Need Y Cb Cr format from RGB */
    for(y=0;y<height;y++)
        for(x=0;x<width;x++) {
            r=g=b=0 ;
       //   off = y*ximg->bytes_per_line + F*x ;
            if ((x < ximg->width) && (y < ximg->height)) {
       //       r = ximg->data[off+2] ;
       //       g = ximg->data[off+1] ;
       //       b = ximg->data[off+0] ;
                long val = XGetPixel(ximg,x,y) ;
                r = val>>16 ;
                g = val>>8 ;
                b = val ;
            }
            pic->data[0][y * pic->linesize[0] + x]         =   0 + 0.299   *r + 0.587   *g + 0.114   *b ;
            if (0==(x&1) && 0==(y&1)) {
                pic->data[1][y/2 * pic->linesize[1] + x/2] = 128 - 0.168736*r - 0.331264*g + 0.5     *b ;
                pic->data[2][y/2 * pic->linesize[2] + x/2] = 128 + 0.5     *r - 0.418688*g - 0.081312*b ;
            }
        }

    return 0 ; //FIXME
}


int write_frame(void *vp, const XImage *ximg)
{
    VidInfo *vi       = (VidInfo *)vp ;
    AVCodecContext *c = vi->strm->codec ;
    AVPacket pkt ;
    int ret = 0 ;

    if (Ximage2Pic(vi->pic, ximg, c->width, c->height)) return 0 ;
 // fill_yuv_image(vi->pic, frame_no, c->width, c->height) ;
    av_init_packet(&pkt) ;

    if (vi->ctx->oformat->flags & AVFMT_RAWPICTURE)
    {
        pkt.flags       |= AV_PKT_FLAG_KEY ;
        pkt.stream_index = vi->strm->index ;
        pkt.data         = (uint8_t *)vi->pic ;
        pkt.size         = sizeof(AVPicture) ;
        ret              = av_interleaved_write_frame(vi->ctx, &pkt) ;
    }
    else
    {
        int out_size = avcodec_encode_video(c, vi->buff, vi->buff_len, vi->pic) ;
        /* if zero size, it means the image was buffered */
        if (out_size > 0) {

            if (c->coded_frame->pts != AV_NOPTS_VALUE)
                pkt.pts         = av_rescale_q(c->coded_frame->pts, c->time_base, vi->strm->time_base) ;
            if(c->coded_frame->key_frame)
                pkt.flags      |= AV_PKT_FLAG_KEY ;
            pkt.stream_index    = vi->strm->index ;
            pkt.data            = vi->buff ;
            pkt.size            = out_size ;
            ret                 = av_interleaved_write_frame(vi->ctx, &pkt) ;
        }
    }
    return ret ;
}
