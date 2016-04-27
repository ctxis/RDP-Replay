/**
 * FreeRDP: A Remote Desktop Protocol Client
 * X11 Client
 *
 * Copyright 2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#ifdef WITH_XCURSOR
#include <X11/Xcursor/Xcursor.h>
#endif

#ifdef WITH_XINERAMA
#include <X11/extensions/Xinerama.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/select.h>
#include <freerdp/constants.h>
#include <freerdp/codec/nsc.h>
#include <freerdp/codec/rfx.h>
#include <freerdp/codec/color.h>
#include <freerdp/codec/bitmap.h>
#include <freerdp/utils/args.h>
#include <freerdp/utils/memory.h>
#include <freerdp/utils/semaphore.h>
#include <freerdp/utils/memory.h>
#include <freerdp/utils/event.h>
#include <freerdp/utils/signal.h>
#include <freerdp/utils/passphrase.h>
#include <freerdp/plugins/cliprdr.h>
#include <freerdp/rail.h>

#include "xf_gdi.h"
#include "xf_rail.h"
#include "xf_tsmf.h"
#include "xf_event.h"
#include "xf_cliprdr.h"
#include "xf_monitor.h"
#include "xf_graphics.h"
#include "xf_keyboard.h"

#include "xfreerdp.h"

static freerdp_sem g_sem;
static int g_thread_count = 0;
static uint8 g_disconnect_reason = 0;

static long xv_port = 0;
static const size_t password_size = 512;

struct thread_data
{
	freerdp* instance;
};

int xf_process_client_args(rdpSettings* settings, const char* opt, const char* val, void* user_data);
int xf_process_plugin_args(rdpSettings* settings, const char* name, RDP_PLUGIN_DATA* plugin_data, void* user_data);

void xf_context_new(freerdp* instance, rdpContext* context)
{
	context->channels = freerdp_channels_new();
}

void xf_context_free(freerdp* instance, rdpContext* context)
{

}

static void draw_cursor(xfInfo *xfi) ;//SE
static void undraw_cursor(xfInfo *xfi) ;//SE
static void out2vid(xfInfo *xfi) ;//SE
void xf_sw_begin_paint(rdpContext* context)
{
xfInfo   *xfi = ((xfContext*)context)->xfi ;//SE
	rdpGdi* gdi = context->gdi;
if (xfi) out2vid(xfi) ;//SE
	gdi->primary->hdc->hwnd->invalid->null = 1;
	gdi->primary->hdc->hwnd->ninvalid = 0;
if (xfi) undraw_cursor(xfi) ;//SE
}

void xf_sw_end_paint(rdpContext* context)
{
	rdpGdi* gdi;
	xfInfo* xfi;
	sint32 x, y;
	uint32 w, h;

	xfi = ((xfContext*) context)->xfi;
	gdi = context->gdi;
if (xfi) draw_cursor(xfi) ;//SE

	if (xfi->remote_app != true)
	{
		if (xfi->complex_regions != true)
		{
			if (gdi->primary->hdc->hwnd->invalid->null)
				return;

			x = gdi->primary->hdc->hwnd->invalid->x;
			y = gdi->primary->hdc->hwnd->invalid->y;
			w = gdi->primary->hdc->hwnd->invalid->w;
			h = gdi->primary->hdc->hwnd->invalid->h;

			XPutImage(xfi->display, xfi->primary, xfi->gc, xfi->image, x, y, x, y, w, h);
			XCopyArea(xfi->display, xfi->primary, xfi->window->handle, xfi->gc, x, y, w, h, x, y);
		}
		else
		{
			int i;
			int ninvalid;
			HGDI_RGN cinvalid;

			if (gdi->primary->hdc->hwnd->ninvalid < 1)
				return;

			ninvalid = gdi->primary->hdc->hwnd->ninvalid;
			cinvalid = gdi->primary->hdc->hwnd->cinvalid;

			for (i = 0; i < ninvalid; i++)
			{
				x = cinvalid[i].x;
				y = cinvalid[i].y;
				w = cinvalid[i].w;
				h = cinvalid[i].h;

				XPutImage(xfi->display, xfi->primary, xfi->gc, xfi->image, x, y, x, y, w, h);
				XCopyArea(xfi->display, xfi->primary, xfi->window->handle, xfi->gc, x, y, w, h, x, y);
			}

			XFlush(xfi->display);
		}
	}
	else
	{
		if (gdi->primary->hdc->hwnd->invalid->null)
			return;

		x = gdi->primary->hdc->hwnd->invalid->x;
		y = gdi->primary->hdc->hwnd->invalid->y;
		w = gdi->primary->hdc->hwnd->invalid->w;
		h = gdi->primary->hdc->hwnd->invalid->h;

		xf_rail_paint(xfi, context->rail, x, y, x + w - 1, y + h - 1);
	}
}

void xf_sw_desktop_resize(rdpContext* context)
{
	xfInfo* xfi;
	rdpSettings* settings;

	xfi = ((xfContext*) context)->xfi;
	settings = xfi->instance->settings;
if (xfi) undraw_cursor(xfi) ;//SE

	if (xfi->fullscreen != true)
	{
		rdpGdi* gdi = context->gdi;
		gdi_resize(gdi, xfi->width, xfi->height);

		if (xfi->image)
		{
			xfi->image->data = NULL;
			XDestroyImage(xfi->image);
			xfi->image = XCreateImage(xfi->display, xfi->visual, xfi->depth, ZPixmap, 0,
					(char*) gdi->primary_buffer, gdi->width, gdi->height, xfi->scanline_pad, 0);
		}
	}
if (xfi) draw_cursor(xfi) ;//SE
}

void xf_hw_begin_paint(rdpContext* context)
{
	xfInfo* xfi;
	xfi = ((xfContext*) context)->xfi;
if (xfi) out2vid(xfi) ;//SE
	xfi->hdc->hwnd->invalid->null = 1;
	xfi->hdc->hwnd->ninvalid = 0;
if (xfi) undraw_cursor(xfi) ;//SE
}

void xf_hw_end_paint(rdpContext* context)
{
	xfInfo* xfi;
	sint32 x, y;
	uint32 w, h;

	xfi = ((xfContext*) context)->xfi;
if (xfi) draw_cursor(xfi) ;//SE

	if (xfi->remote_app)
	{
		if (xfi->hdc->hwnd->invalid->null)
			return;

		x = xfi->hdc->hwnd->invalid->x;
		y = xfi->hdc->hwnd->invalid->y;
		w = xfi->hdc->hwnd->invalid->w;
		h = xfi->hdc->hwnd->invalid->h;

		xf_rail_paint(xfi, context->rail, x, y, x + w - 1, y + h - 1);
	}
}

void xf_hw_desktop_resize(rdpContext* context)
{
	xfInfo* xfi;
	boolean same;
	rdpSettings* settings;

	xfi = ((xfContext*) context)->xfi;
	settings = xfi->instance->settings;
if (xfi) undraw_cursor(xfi) ;//SE

	if (xfi->fullscreen != true)
	{
		xfi->width = settings->width;
		xfi->height = settings->height;

		if (xfi->window)
			xf_ResizeDesktopWindow(xfi, xfi->window, settings->width, settings->height);

		if (xfi->primary)
		{
			same = (xfi->primary == xfi->drawing) ? true : false;

			XFreePixmap(xfi->display, xfi->primary);

			xfi->primary = XCreatePixmap(xfi->display, xfi->drawable,
					xfi->width, xfi->height, xfi->depth);

			if (same)
				xfi->drawing = xfi->primary;
		}
	}
if (xfi) draw_cursor(xfi) ;//SE
}

boolean xf_get_fds(freerdp* instance, void** rfds, int* rcount, void** wfds, int* wcount)
{
	xfInfo* xfi = ((xfContext*) instance->context)->xfi;

	rfds[*rcount] = (void*)(long)(xfi->xfds);
	(*rcount)++;

	return true;
}

boolean xf_check_fds(freerdp* instance, fd_set* set)
{
	XEvent xevent;
	xfInfo* xfi = ((xfContext*) instance->context)->xfi;

	while (XPending(xfi->display))
	{
		memset(&xevent, 0, sizeof(xevent));
		XNextEvent(xfi->display, &xevent);

		if (xf_event_process(instance, &xevent) != true)
			return false;
	}

	return true;
}

void xf_create_window(xfInfo* xfi)
{
	XEvent xevent;
	char* win_title;
	int width, height;

	width = xfi->width;
	height = xfi->height;

	xfi->attribs.background_pixel = BlackPixelOfScreen(xfi->screen);
	xfi->attribs.border_pixel = WhitePixelOfScreen(xfi->screen);
	xfi->attribs.backing_store = xfi->primary ? NotUseful : Always;
	xfi->attribs.override_redirect = xfi->fullscreen;
	xfi->attribs.colormap = xfi->colormap;
	xfi->attribs.bit_gravity = ForgetGravity;
	xfi->attribs.win_gravity = StaticGravity;

	if (xfi->instance->settings->window_title != NULL)
	{
		win_title = xstrdup(xfi->instance->settings->window_title);
	}
	else if (xfi->instance->settings->port == 3389)
	{
		win_title = xmalloc(1 + sizeof("FreeRDP: ") + strlen(xfi->instance->settings->hostname));
		sprintf(win_title, "FreeRDP: %s", xfi->instance->settings->hostname);
	}
	else
	{
		win_title = xmalloc(1 + sizeof("FreeRDP: ") + strlen(xfi->instance->settings->hostname) + sizeof(":00000"));
		sprintf(win_title, "FreeRDP: %s:%i", xfi->instance->settings->hostname, xfi->instance->settings->port);
	}

	xfi->window = xf_CreateDesktopWindow(xfi, win_title, width, height, xfi->decorations);
	xfree(win_title);

	if (xfi->parent_window)
		XReparentWindow(xfi->display, xfi->window->handle, xfi->parent_window, 0, 0);

	if (xfi->fullscreen)
		xf_SetWindowFullscreen(xfi, xfi->window, xfi->fullscreen);

	/* wait for VisibilityNotify */
	do
	{
		XMaskEvent(xfi->display, VisibilityChangeMask, &xevent);
	}
	while (xevent.type != VisibilityNotify);

	xfi->unobscured = (xevent.xvisibility.state == VisibilityUnobscured);

	XSetWMProtocols(xfi->display, xfi->window->handle, &(xfi->WM_DELETE_WINDOW), 1);
	xfi->drawable = xfi->window->handle;
}

void xf_toggle_fullscreen(xfInfo* xfi)
{
	Pixmap contents = 0;

	contents = XCreatePixmap(xfi->display, xfi->window->handle, xfi->width, xfi->height, xfi->depth);
	XCopyArea(xfi->display, xfi->primary, contents, xfi->gc, 0, 0, xfi->width, xfi->height, 0, 0);

	XDestroyWindow(xfi->display, xfi->window->handle);
	xfi->fullscreen = (xfi->fullscreen) ? false : true;
	xf_create_window(xfi);

	XCopyArea(xfi->display, contents, xfi->primary, xfi->gc, 0, 0, xfi->width, xfi->height, 0, 0);
	XFreePixmap(xfi->display, contents);
}

boolean xf_get_pixmap_info(xfInfo* xfi)
{
	int i;
	int vi_count;
	int pf_count;
	XVisualInfo* vi;
	XVisualInfo* vis;
	XVisualInfo template;
	XPixmapFormatValues* pf;
	XPixmapFormatValues* pfs;

	pfs = XListPixmapFormats(xfi->display, &pf_count);

	if (pfs == NULL)
	{
		printf("xf_get_pixmap_info: XListPixmapFormats failed\n");
		return 1;
	}

	for (i = 0; i < pf_count; i++)
	{
		pf = pfs + i;

		if (pf->depth == xfi->depth)
		{
			xfi->bpp = pf->bits_per_pixel;
			xfi->scanline_pad = pf->scanline_pad;
			break;
		}
	}
	XFree(pfs);

	memset(&template, 0, sizeof(template));
	template.class = TrueColor;
	template.screen = xfi->screen_number;

	vis = XGetVisualInfo(xfi->display, VisualClassMask | VisualScreenMask, &template, &vi_count);

	if (vis == NULL)
	{
		printf("xf_get_pixmap_info: XGetVisualInfo failed\n");
		return false;
	}

	vi = NULL;
	for (i = 0; i < vi_count; i++)
	{
		vi = vis + i;

		if (vi->depth == xfi->depth)
		{
			xfi->visual = vi->visual;
			break;
		}
	}

	if (vi)
	{
		/*
		 * Detect if the server visual has an inverted colormap
		 * (BGR vs RGB, or red being the least significant byte)
		 */

		if (vi->red_mask & 0xFF) 
		{
			xfi->clrconv->invert = true;
		}
	}

	XFree(vis);

	if ((xfi->visual == NULL) || (xfi->scanline_pad == 0))
	{
		return false;
	}

	return true;
}

static int (*_def_error_handler)(Display*, XErrorEvent*);
int xf_error_handler(Display* d, XErrorEvent* ev)
{
	char buf[256];
	int do_abort = true;

	XGetErrorText(d, ev->error_code, buf, sizeof(buf));
	printf("%s", buf);

	if (do_abort)
		abort();

	_def_error_handler(d, ev);

	return false;
}

int _xf_error_handler(Display* d, XErrorEvent* ev)
{
	/*
 	 * ungrab the keyboard, in case a debugger is running in
 	 * another window. This make xf_error_handler() a potential
 	 * debugger breakpoint.
 	 */
	XUngrabKeyboard(d, CurrentTime);
	return xf_error_handler(d, ev);
}

boolean xf_pre_connect(freerdp* instance)
{
	xfInfo* xfi;
	boolean bitmap_cache;
	rdpSettings* settings;
	int arg_parse_result;
	
	xfi = (xfInfo*) xzalloc(sizeof(xfInfo));
	((xfContext*) instance->context)->xfi = xfi;

	xfi->_context = instance->context;
	xfi->context = (xfContext*) instance->context;
	xfi->context->settings = instance->settings;
	xfi->instance = instance;
	
	arg_parse_result = freerdp_parse_args(instance->settings, instance->context->argc,instance->context->argv,
				xf_process_plugin_args, instance->context->channels, xf_process_client_args, xfi);
	
	if (arg_parse_result < 0)
	{
		if (arg_parse_result == FREERDP_ARGS_PARSE_FAILURE)
			printf("failed to parse arguments.\n");
		
		exit(XF_EXIT_PARSE_ARGUMENTS);
	}

	settings = instance->settings;
	bitmap_cache = settings->bitmap_cache;

	settings->os_major_type = OSMAJORTYPE_UNIX;
	settings->os_minor_type = OSMINORTYPE_NATIVE_XSERVER;

	settings->order_support[NEG_DSTBLT_INDEX] = true;
	settings->order_support[NEG_PATBLT_INDEX] = true;
	settings->order_support[NEG_SCRBLT_INDEX] = true;
	settings->order_support[NEG_OPAQUE_RECT_INDEX] = true;
	settings->order_support[NEG_DRAWNINEGRID_INDEX] = false;
	settings->order_support[NEG_MULTIDSTBLT_INDEX] = false;
	settings->order_support[NEG_MULTIPATBLT_INDEX] = false;
	settings->order_support[NEG_MULTISCRBLT_INDEX] = false;
	settings->order_support[NEG_MULTIOPAQUERECT_INDEX] = true;
	settings->order_support[NEG_MULTI_DRAWNINEGRID_INDEX] = false;
	settings->order_support[NEG_LINETO_INDEX] = true;
	settings->order_support[NEG_POLYLINE_INDEX] = true;
	settings->order_support[NEG_MEMBLT_INDEX] = bitmap_cache;

	settings->order_support[NEG_MEM3BLT_INDEX] = (settings->sw_gdi) ? true : false;

	settings->order_support[NEG_MEMBLT_V2_INDEX] = bitmap_cache;
	settings->order_support[NEG_MEM3BLT_V2_INDEX] = false;
	settings->order_support[NEG_SAVEBITMAP_INDEX] = false;
	settings->order_support[NEG_GLYPH_INDEX_INDEX] = true;
	settings->order_support[NEG_FAST_INDEX_INDEX] = true;
	settings->order_support[NEG_FAST_GLYPH_INDEX] = true;

	settings->order_support[NEG_POLYGON_SC_INDEX] = (settings->sw_gdi) ? false : true;
	settings->order_support[NEG_POLYGON_CB_INDEX] = (settings->sw_gdi) ? false : true;

	settings->order_support[NEG_ELLIPSE_SC_INDEX] = false;
	settings->order_support[NEG_ELLIPSE_CB_INDEX] = false;

	freerdp_channels_pre_connect(xfi->_context->channels, instance);

	xfi->display = XOpenDisplay(NULL);

	if (xfi->display == NULL)
	{
		printf("xf_pre_connect: failed to open display: %s\n", XDisplayName(NULL));
		printf("Please check that the $DISPLAY environment variable is properly set.\n");
		return false;
	}

	if (xfi->debug)
	{
		printf("Enabling X11 debug mode.\n");
		XSynchronize(xfi->display, true);
		_def_error_handler = XSetErrorHandler(_xf_error_handler);
	}

	xfi->_NET_WM_ICON = XInternAtom(xfi->display, "_NET_WM_ICON", False);
	xfi->_MOTIF_WM_HINTS = XInternAtom(xfi->display, "_MOTIF_WM_HINTS", False);
	xfi->_NET_CURRENT_DESKTOP = XInternAtom(xfi->display, "_NET_CURRENT_DESKTOP", False);
	xfi->_NET_WORKAREA = XInternAtom(xfi->display, "_NET_WORKAREA", False);
	xfi->_NET_WM_STATE = XInternAtom(xfi->display, "_NET_WM_STATE", False);
	xfi->_NET_WM_STATE_FULLSCREEN = XInternAtom(xfi->display, "_NET_WM_STATE_FULLSCREEN", False);
	xfi->_NET_WM_WINDOW_TYPE = XInternAtom(xfi->display, "_NET_WM_WINDOW_TYPE", False);

	xfi->_NET_WM_WINDOW_TYPE_NORMAL = XInternAtom(xfi->display, "_NET_WM_WINDOW_TYPE_NORMAL", False);
	xfi->_NET_WM_WINDOW_TYPE_DIALOG = XInternAtom(xfi->display, "_NET_WM_WINDOW_TYPE_DIALOG", False);
	xfi->_NET_WM_WINDOW_TYPE_POPUP= XInternAtom(xfi->display, "_NET_WM_WINDOW_TYPE_POPUP", False);
	xfi->_NET_WM_WINDOW_TYPE_UTILITY = XInternAtom(xfi->display, "_NET_WM_WINDOW_TYPE_UTILITY", False);
	xfi->_NET_WM_WINDOW_TYPE_DROPDOWN_MENU = XInternAtom(xfi->display, "_NET_WM_WINDOW_TYPE_DROPDOWN_MENU", False);
	xfi->_NET_WM_STATE_SKIP_TASKBAR = XInternAtom(xfi->display, "_NET_WM_STATE_SKIP_TASKBAR", False);
	xfi->_NET_WM_STATE_SKIP_PAGER = XInternAtom(xfi->display, "_NET_WM_STATE_SKIP_PAGER", False);
	xfi->_NET_WM_MOVERESIZE = XInternAtom(xfi->display, "_NET_WM_MOVERESIZE", False);
	xfi->_NET_MOVERESIZE_WINDOW = XInternAtom(xfi->display, "_NET_MOVERESIZE_WINDOW", False);

	xfi->WM_PROTOCOLS = XInternAtom(xfi->display, "WM_PROTOCOLS", False);
	xfi->WM_DELETE_WINDOW = XInternAtom(xfi->display, "WM_DELETE_WINDOW", False);

	xf_kbd_init(xfi);

	xfi->clrconv = freerdp_clrconv_new(CLRCONV_ALPHA);

	instance->context->cache = cache_new(instance->settings);

	xfi->xfds = ConnectionNumber(xfi->display);
	xfi->screen_number = DefaultScreen(xfi->display);
	xfi->screen = ScreenOfDisplay(xfi->display, xfi->screen_number);
	xfi->depth = DefaultDepthOfScreen(xfi->screen);
	xfi->big_endian = (ImageByteOrder(xfi->display) == MSBFirst);

	xfi->mouse_motion = settings->mouse_motion;
	xfi->complex_regions = true;
	xfi->decorations = settings->decorations;
	xfi->fullscreen = settings->fullscreen;
	xfi->grab_keyboard = settings->grab_keyboard;
	xfi->fullscreen_toggle = true;
	xfi->sw_gdi = settings->sw_gdi;
	xfi->parent_window = (Window) settings->parent_window_xid;

	xf_detect_monitors(xfi, settings);

	return true;
}

void cpuid(unsigned info, unsigned *eax, unsigned *ebx, unsigned *ecx, unsigned *edx)
{
#ifdef __GNUC__
#if defined(__i386__) || defined(__x86_64__)
	*eax = info;
	__asm volatile
		("mov %%ebx, %%edi;" /* 32bit PIC: don't clobber ebx */
		 "cpuid;"
		 "mov %%ebx, %%esi;"
		 "mov %%edi, %%ebx;"
		 :"+a" (*eax), "=S" (*ebx), "=c" (*ecx), "=d" (*edx)
		 : :"edi");
#endif
#endif
}
 
uint32 xf_detect_cpu()
{
	unsigned int eax, ebx, ecx, edx = 0;
	uint32 cpu_opt = 0;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	if (edx & (1<<26)) 
	{
		DEBUG("SSE2 detected");
		cpu_opt |= CPU_SSE2;
	}

	return cpu_opt;
}

boolean xf_post_connect(freerdp* instance)
{
	xfInfo* xfi;
	XGCValues gcv;
	rdpCache* cache;
	rdpChannels* channels;
	RFX_CONTEXT* rfx_context = NULL;

	xfi = ((xfContext*) instance->context)->xfi;
	cache = instance->context->cache;
	channels = xfi->_context->channels;

	if (xf_get_pixmap_info(xfi) != true)
		return false;

	xf_register_graphics(instance->context->graphics);

	if (xfi->sw_gdi)
	{
		rdpGdi* gdi;
		uint32 flags;

		flags = CLRCONV_ALPHA;

		if (xfi->bpp > 16)
			flags |= CLRBUF_32BPP;
		else
			flags |= CLRBUF_16BPP;

		gdi_init(instance, flags, NULL);
		gdi = instance->context->gdi;
		xfi->primary_buffer = gdi->primary_buffer;

		rfx_context = gdi->rfx_context;
	}
	else
	{
		xfi->srcBpp = instance->settings->color_depth;
		xf_gdi_register_update_callbacks(instance->update);

		xfi->hdc = gdi_CreateDC(xfi->clrconv, xfi->bpp);

		if (instance->settings->rfx_codec)
		{
			rfx_context = (void*) rfx_context_new();
			xfi->rfx_context = rfx_context;
		}

		if (instance->settings->ns_codec)
			xfi->nsc_context = (void*) nsc_context_new();
	}

	if (rfx_context)
	{
#ifdef WITH_SSE2
		/* detect only if needed */
		rfx_context_set_cpu_opt(rfx_context, xf_detect_cpu());
#endif
	}

	xfi->width = instance->settings->width;
	xfi->height = instance->settings->height;

	xf_create_window(xfi);

	memset(&gcv, 0, sizeof(gcv));
	xfi->modifier_map = XGetModifierMapping(xfi->display);

	xfi->gc = XCreateGC(xfi->display, xfi->drawable, GCGraphicsExposures, &gcv);
	xfi->primary = XCreatePixmap(xfi->display, xfi->drawable, xfi->width, xfi->height, xfi->depth);
	xfi->drawing = xfi->primary;

	xfi->bitmap_mono = XCreatePixmap(xfi->display, xfi->drawable, 8, 8, 1);
	xfi->gc_mono = XCreateGC(xfi->display, xfi->bitmap_mono, GCGraphicsExposures, &gcv);

	XSetForeground(xfi->display, xfi->gc, BlackPixelOfScreen(xfi->screen));
	XFillRectangle(xfi->display, xfi->primary, xfi->gc, 0, 0, xfi->width, xfi->height);

	xfi->image = XCreateImage(xfi->display, xfi->visual, xfi->depth, ZPixmap, 0,
			(char*) xfi->primary_buffer, xfi->width, xfi->height, xfi->scanline_pad, 0);

	xfi->bmp_codec_none = (uint8*) xmalloc(64 * 64 * 4);

	if (xfi->sw_gdi)
	{
		instance->update->BeginPaint = xf_sw_begin_paint;
		instance->update->EndPaint = xf_sw_end_paint;
		instance->update->DesktopResize = xf_sw_desktop_resize;
	}
	else
	{
		instance->update->BeginPaint = xf_hw_begin_paint;
		instance->update->EndPaint = xf_hw_end_paint;
		instance->update->DesktopResize = xf_hw_desktop_resize;
	}

	pointer_cache_register_callbacks(instance->update);

	if (xfi->sw_gdi != true)
	{
		glyph_cache_register_callbacks(instance->update);
		brush_cache_register_callbacks(instance->update);
		bitmap_cache_register_callbacks(instance->update);
		offscreen_cache_register_callbacks(instance->update);
		palette_cache_register_callbacks(instance->update);
	}

	instance->context->rail = rail_new(instance->settings);
	rail_register_update_callbacks(instance->context->rail, instance->update);
	xf_rail_register_callbacks(xfi, instance->context->rail);

	freerdp_channels_post_connect(channels, instance);

	xf_tsmf_init(xfi, xv_port);

	xf_cliprdr_init(xfi, channels);

	return true;
}

boolean xf_authenticate(freerdp* instance, char** username, char** password, char** domain)
{
	*password = xmalloc(password_size * sizeof(char));

	if (freerdp_passphrase_read("Password: ", *password, password_size) == NULL)
		return false;

	return true;
}

boolean xf_verify_certificate(freerdp* instance, char* subject, char* issuer, char* fingerprint)
{
	char answer;

	printf("Certificate details:\n");
	printf("\tSubject: %s\n", subject);
	printf("\tIssuer: %s\n", issuer);
	printf("\tThumbprint: %s\n", fingerprint);
	printf("The above X.509 certificate could not be verified, possibly because you do not have "
		"the CA certificate in your certificate store, or the certificate has expired. "
		"Please look at the documentation on how to create local certificate store for a private CA.\n");

	while (1)
	{
		printf("Do you trust the above certificate? (Y/N) ");
		answer = fgetc(stdin);

		if (answer == 'y' || answer == 'Y')
		{
			return true;
		}
		else if (answer == 'n' || answer == 'N')
		{
			break;
		}
		printf("\n");
	}

	return false;
}

int xf_process_client_args(rdpSettings* settings, const char* opt, const char* val, void* user_data)
{
	int argc = 0;
	xfInfo* xfi = (xfInfo*) user_data;

	if (strcmp("--kbd-list", opt) == 0)
	{
		int i;
		RDP_KEYBOARD_LAYOUT* layouts;

		layouts = freerdp_keyboard_get_layouts(RDP_KEYBOARD_LAYOUT_TYPE_STANDARD);

		printf("\nKeyboard Layouts\n");
		for (i = 0; layouts[i].code; i++)
		{
			printf("0x%08X\t%s\n", layouts[i].code, layouts[i].name);
			xfree(layouts[i].name);
		}
		xfree(layouts);

		layouts = freerdp_keyboard_get_layouts(RDP_KEYBOARD_LAYOUT_TYPE_VARIANT);

		printf("\nKeyboard Layout Variants\n");
		for (i = 0; layouts[i].code; i++)
		{
			printf("0x%08X\t%s\n", layouts[i].code, layouts[i].name);
			xfree(layouts[i].name);
		}
		xfree(layouts);

		layouts = freerdp_keyboard_get_layouts(RDP_KEYBOARD_LAYOUT_TYPE_IME);

		printf("\nKeyboard Input Method Editors (IMEs)\n");
		for (i = 0; layouts[i].code; i++)
		{
			printf("0x%08X\t%s\n", layouts[i].code, layouts[i].name);
			xfree(layouts[i].name);
		}
		xfree(layouts);

		exit(0);
	}
	else if (strcmp("--xv-port", opt) == 0)
	{
		xv_port = atoi(val);
		argc = 2;
	}
	else if (strcmp("--dbg-x11", opt) == 0)
	{
		xfi->debug = true;
		argc = 1;
	}

	return argc;
}

int xf_process_plugin_args(rdpSettings* settings, const char* name, RDP_PLUGIN_DATA* plugin_data, void* user_data)
{
	rdpChannels* channels = (rdpChannels*) user_data;

	printf("loading plugin %s\n", name);
	freerdp_channels_load_plugin(channels, settings, name, plugin_data);

	return 1;
}

int xf_receive_channel_data(freerdp* instance, int channelId, uint8* data, int size, int flags, int total_size)
{
	return freerdp_channels_data(instance, channelId, data, size, flags, total_size);
}

void xf_process_channel_event(rdpChannels* chanman, freerdp* instance)
{
	xfInfo* xfi;
	RDP_EVENT* event;

	xfi = ((xfContext*) instance->context)->xfi;

	event = freerdp_channels_pop_event(chanman);

	if (event)
	{
		switch (event->event_class)
		{
			case RDP_EVENT_CLASS_RAIL:
				xf_process_rail_event(xfi, chanman, event);
				break;

			case RDP_EVENT_CLASS_TSMF:
				xf_process_tsmf_event(xfi, event);
				break;

			case RDP_EVENT_CLASS_CLIPRDR:
				xf_process_cliprdr_event(xfi, event);
				break;

			default:
				break;
		}

		freerdp_event_free(event);
	}
}

void xf_window_free(xfInfo* xfi)
{
	rdpContext* context = xfi->instance->context;

	XFreeModifiermap(xfi->modifier_map);
	xfi->modifier_map = 0;

	XFreeGC(xfi->display, xfi->gc);
	xfi->gc = 0;

	XFreeGC(xfi->display, xfi->gc_mono);
	xfi->gc_mono = 0;

	if (xfi->window != NULL)
	{
		xf_DestroyWindow(xfi, xfi->window);
		xfi->window = NULL;
	}

	if (xfi->primary)
	{
		XFreePixmap(xfi->display, xfi->primary);
		xfi->primary = 0;
	}

	if (xfi->image)
	{
		xfi->image->data = NULL;
		XDestroyImage(xfi->image);
		xfi->image = NULL;
	}

	if (context != NULL)
	{
			cache_free(context->cache);
			context->cache = NULL;

			rail_free(context->rail);
			context->rail = NULL;
	}

	if (xfi->rfx_context) 
	{
		rfx_context_free(xfi->rfx_context);
		xfi->rfx_context = NULL;
	}

	freerdp_clrconv_free(xfi->clrconv);

	if (xfi->hdc)
		gdi_DeleteDC(xfi->hdc);

	xf_tsmf_uninit(xfi);
	xf_cliprdr_uninit(xfi);
}

void xf_free(xfInfo* xfi)
{
	xf_window_free(xfi);

	xfree(xfi->bmp_codec_none);

	XCloseDisplay(xfi->display);

	xfree(xfi);
}

int xfreerdp_run(freerdp* instance)
{
	int i;
	int fds;
	xfInfo* xfi;
	int max_fds;
	int rcount;
	int wcount;
	int ret = 0;
	void* rfds[32];
	void* wfds[32];
	fd_set rfds_set;
	fd_set wfds_set;
	int select_status;
	rdpChannels* channels;
	struct timeval timeout;

	memset(rfds, 0, sizeof(rfds));
	memset(wfds, 0, sizeof(wfds));
	memset(&timeout, 0, sizeof(struct timeval));

	if (!freerdp_connect(instance))
		return XF_EXIT_CONN_FAILED;

	xfi = ((xfContext*) instance->context)->xfi;
	channels = instance->context->channels;

	while (!xfi->disconnect && !freerdp_shall_disconnect(instance))
	{
		rcount = 0;
		wcount = 0;

		if (freerdp_get_fds(instance, rfds, &rcount, wfds, &wcount) != true)
		{
			printf("Failed to get FreeRDP file descriptor\n");
			ret = XF_EXIT_CONN_FAILED;
			break;
		}
		if (freerdp_channels_get_fds(channels, instance, rfds, &rcount, wfds, &wcount) != true)
		{
			printf("Failed to get channel manager file descriptor\n");
			ret = XF_EXIT_CONN_FAILED;
			break;
		}
		if (xf_get_fds(instance, rfds, &rcount, wfds, &wcount) != true)
		{
			printf("Failed to get xfreerdp file descriptor\n");
			ret = XF_EXIT_CONN_FAILED;
			break;
		}

		max_fds = 0;
		FD_ZERO(&rfds_set);
		FD_ZERO(&wfds_set);

		for (i = 0; i < rcount; i++)
		{
			fds = (int)(long)(rfds[i]);

			if (fds > max_fds)
				max_fds = fds;

			FD_SET(fds, &rfds_set);
		}

		if (max_fds == 0)
			break;

		timeout.tv_sec = 5;
		select_status = select(max_fds + 1, &rfds_set, &wfds_set, NULL, &timeout);

		if (select_status == 0)
		{
			//freerdp_send_keep_alive(instance);
			continue;
		}
		else if (select_status == -1)
		{
			/* these are not really errors */
			if (!((errno == EAGAIN) ||
				(errno == EWOULDBLOCK) ||
				(errno == EINPROGRESS) ||
				(errno == EINTR))) /* signal occurred */
			{
				printf("xfreerdp_run: select failed\n");
				break;
			}
		}

		if (freerdp_check_fds(instance) != true)
		{
			printf("Failed to check FreeRDP file descriptor\n");
			break;
		}
		if (xf_check_fds(instance, &rfds_set) != true)
		{
			printf("Failed to check xfreerdp file descriptor\n");
			break;
		}
		if (freerdp_channels_check_fds(channels, instance) != true)
		{
			printf("Failed to check channel manager file descriptor\n");
			break;
		}
		xf_process_channel_event(channels, instance);
	}

	if (!ret)
		ret = freerdp_error_info(instance);

	freerdp_channels_close(channels, instance);
	freerdp_channels_free(channels);
	freerdp_disconnect(instance);
	gdi_free(instance);
	xf_free(xfi);

	freerdp_free(instance);

	return ret;
}

void* thread_func(void* param)
{
	struct thread_data* data;
	data = (struct thread_data*) param;

	g_disconnect_reason = xfreerdp_run(data->instance);

	xfree(data);

	pthread_detach(pthread_self());

	g_thread_count--;

        if (g_thread_count < 1)
                freerdp_sem_signal(g_sem);

	pthread_exit(NULL);
}

static uint8 exit_code_from_disconnect_reason(uint32 reason)
{
	if (reason == 0 ||
	   (reason >= XF_EXIT_PARSE_ARGUMENTS && reason <= XF_EXIT_CONN_FAILED))
		 return reason;

	/* Licence error set */
	else if (reason >= 0x100 && reason <= 0x10A)
		 reason -= 0x100 + XF_EXIT_LICENSE_INTERNAL;

	/* RDP protocol error set */
	else if (reason >= 0x10c9 && reason <= 0x1193)
		 reason = XF_EXIT_RDP;

	/* There's no need to test protocol-independent codes: they match */
	else if (!(reason <= 0xB))
		 reason = XF_EXIT_UNKNOWN;

	return reason;
}

freerdp* INstance;
int was_main(int argc, char* argv[])
{
	pthread_t thread;
	struct thread_data* data;

	freerdp_handle_signals();

	setlocale(LC_ALL, "");

	freerdp_channels_global_init();

	g_sem = freerdp_sem_new(1);

	INstance = freerdp_new();
	INstance->PreConnect = xf_pre_connect;
	INstance->PostConnect = xf_post_connect;
	INstance->Authenticate = xf_authenticate;
	INstance->VerifyCertificate = xf_verify_certificate;
	INstance->ReceiveChannelData = xf_receive_channel_data;

	INstance->context_size = sizeof(xfContext);
	INstance->ContextNew = (pContextNew) xf_context_new;
	INstance->ContextFree = (pContextFree) xf_context_free;
	freerdp_context_new(INstance);

	INstance->context->argc = argc;
	INstance->context->argv = argv;
	INstance->settings->sw_gdi = false;

	data = (struct thread_data*) xzalloc(sizeof(struct thread_data));
	data->instance = INstance;

return 0 ;//SE
	g_thread_count++;
	pthread_create(&thread, 0, thread_func, data);

	while (g_thread_count > 0)
	{
                freerdp_sem_wait(g_sem);
	}

	freerdp_channels_global_uninit();

	return exit_code_from_disconnect_reason(g_disconnect_reason);
}




//=============================================
//
// From here are additions for RDP replay
//
//=============================================
#include "rdp.h"
#define __rdp_private__
#include "librdp.h"

// FIXME: globals should be removed
uint8 *SE_decompress_rdp(rdpRdp*, uint8*, int, int, uint32*) ;
static int                     playOK = 0 ;
static struct rdp_rdp          requestRdp, responseRdp ;
static struct rdp_settings     requestSet, responseSet ;

extern int play_sw_gdi ;
extern int warning ;
extern int do_pointer ;
extern int play_paused ;
extern int trace_ord ;


static void play_init_struct(struct rdp_rdp *rdp, struct rdp_settings *set)
{
    memset(rdp, 0, sizeof(struct rdp_rdp)) ;
    memset(set, 0, sizeof(struct rdp_settings)) ;
    rdp->settings = set ;
    rdp->mppc = mppc_new(rdp) ;
}


static int play_response_init(uint8_t *cli, uint8_t *ser, uint32_t enc_type)
{
    void set_cli_rand(uint8_t *rand) ;
    struct rdp_rdp *rdp = INstance->context->rdp ;
    rdpBlob s_rand_blob ;
    void *old ;
    int rv ;

    if (!rdp->settings) return 0 ;

    old = rdp->settings->server_random ;
    rdp->settings->server_random     = &s_rand_blob ;
    rdp->settings->encryption_method = enc_type ;
    s_rand_blob.data                 = ser ;
    s_rand_blob.length               = 32 ;
    rv = security_establish_keys(cli, rdp) ;
    rdp->settings->server_random     = old ;
    if (!rv) return 0 ;

    // Taken from: rdp_server_establish_keys
    rdp->do_crypt = true;
    if (rdp->settings->salted_checksum) rdp->do_secure_checksum = true;
    if (rdp->settings->encryption_method == ENCRYPTION_METHOD_FIPS)
    {
        uint8 fips_ivec[8] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        rdp->fips_encrypt = crypto_des3_encrypt_init(rdp->fips_encrypt_key, fips_ivec);
        rdp->fips_decrypt = crypto_des3_decrypt_init(rdp->fips_decrypt_key, fips_ivec);
        rdp->fips_hmac = crypto_hmac_new();
    }
    else
    {
        rdp->rc4_decrypt_key = crypto_rc4_init(rdp->decrypt_key, rdp->rc4_key_len);
        rdp->rc4_encrypt_key = crypto_rc4_init(rdp->encrypt_key, rdp->rc4_key_len);
    }

    rdp->state = CONNECTION_STATE_LICENSE ;
    return 1 ;
}


static int play_local_crypt_init(struct rdp_rdp *rdp,
                                 uint8_t *cli,
                                 uint8_t *ser,
                                 uint32_t enc_type)
{
    rdpBlob s_rand_blob ;
    struct rdp_settings *set = rdp->settings ;

    s_rand_blob.data       = ser ;
    s_rand_blob.length     = 32 ;
    rdp->decrypt_use_count = 0 ;
    set->server_random     = &s_rand_blob ;
    set->encryption_method = enc_type ;
    set->salted_checksum   = 1 ;
    set->server_mode       = rdp==&requestRdp ;

    if (!security_establish_keys(cli, rdp)) return 0 ;

    // Taken from: rdp_server_establish_keys
    rdp->do_crypt = true;
    if (rdp->settings->salted_checksum)
        rdp->do_secure_checksum = true;

    if (rdp->settings->encryption_method == ENCRYPTION_METHOD_FIPS)
    {
        uint8 fips_ivec[8] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
        rdp->fips_encrypt  = crypto_des3_encrypt_init(rdp->fips_encrypt_key, fips_ivec);
        rdp->fips_decrypt  = crypto_des3_decrypt_init(rdp->fips_decrypt_key, fips_ivec);

        rdp->fips_hmac     = crypto_hmac_new();
    }
    else
    {
        rdp->rc4_decrypt_key = crypto_rc4_init(rdp->decrypt_key, rdp->rc4_key_len);
        rdp->rc4_encrypt_key = crypto_rc4_init(rdp->encrypt_key, rdp->rc4_key_len);
    }

    // Done. Clean and exit.
    set->server_random = 0 ; // Clear out-of-scope data!
    return 1 ;
}


int play_pre_init(ctx_rdp *ctx)
{
    play_init_struct(&requestRdp,  &requestSet) ;
    play_init_struct(&responseRdp, &responseSet) ;
    INstance->settings->sw_gdi       = SW_GDI(ctx) ;
    INstance->settings->window_title = "RDP Replay" ;
    INstance->settings->color_depth  = 8 ;
    if (!SKIP_GFX(ctx)) if (0==xf_pre_connect(INstance)) return 0 ;
    return 1 ;
}


int play_post_init(ctx_rdp *ctx)
{
    if (SKIP_GFX(ctx)) return 1 ;
    if (0==xf_post_connect(INstance)) return 0 ;
    return 1 ;
}


int play_crypt_init(ctx_rdp *ctx)
{
    uint8_t *cli        = ctx->client_random ;
    uint8_t *ser        = ctx->server_random ;
    uint32_t enc_type   = ctx->use_enc_type ;
    if (0==play_pre_init(ctx)) return 0 ;
    if (0==play_local_crypt_init(&requestRdp, cli,ser,enc_type)) return 0 ;
    if (0==play_local_crypt_init(&responseRdp, cli,ser,enc_type)) return 0 ;
    if (0==play_response_init(cli,ser,enc_type)) return 0 ;
    if (0==play_post_init(ctx)) return 0 ;

    playOK = 1 ; // Now OK to use
    return 1 ;
}


uint8_t *play_response_decrypt(uint8_t *p, uint8_t *max, uint16 flags)
{
    STREAM s ;
    if (!playOK) return 0 ; // Not valid :(
    s.size = (int)(max-p) ;
    s.p    = p ;
    s.data = p ;
    if (!rdp_decrypt(&responseRdp, &s, s.size, flags)) return 0 ;
    return s.p ;
}


uint8_t *play_request_decrypt(uint8_t *p, uint8_t *max, uint16 flags)
{
    STREAM s ;
    if (!playOK) return 0 ; // Not valid :(
    s.size = (int)(max-p) ;
    s.p    = p ;
    s.data = p ;
    if (!rdp_decrypt(&requestRdp, &s, s.size, flags)) return 0 ;
    return s.p ;
}


void set_pars(int bpp, int width, int height)
{
    INstance->settings->width       = width ;
    INstance->settings->height      = height ;
    INstance->settings->color_depth = bpp ;
    if ( ((xfContext*)(INstance->context))->xfi) {
        ((xfContext*)(INstance->context))->xfi->srcBpp = bpp ;
 //     ((xfContext*)(INstance->context))->xfi->bpp = bpp ;
 //     ((xfContext*)(INstance->context))->xfi->depth = bpp ;
        INstance->update->DesktopResize(INstance->context) ;
    }
}


void play_set_glyph_v2(int val)
{
    if ( INstance->context &&
         INstance->context->rdp &&
         INstance->context->rdp->update &&
         INstance->context->rdp->update->secondary)
        INstance->context->rdp->update->secondary->glyph_v2 = val ;
    else
        printf("ERROR: Cannot set glyph_v2 to %s\n",val?"true":"false") ;
}


int play_response_slow(uint8_t *p, uint8_t *max, int chan, int flo)
{
    STREAM ss, *s ;
    struct rdp_rdp *rdp ;
    uint16 pduType;
    uint16 pduLength;
    uint16 pduSource;
 // printf("Flags:%04x chan:%d", flo, chan) ;
 // se_out(" - Slow DATA: ",p,max) ;

    // From 2.2.8.1.1.1.1 Share Control Header
    //   totalLength (2 bytes): A 16-bit unsigned integer. The total length of the packet in bytes (the length includes the size of the Share Control Header). If the totalLength field equals 0x8000, then the Share Control Header and any data that follows MAY be interpreted as a T.128 FlowPDU as described in [T128] section 8.5 (the ASN.1 structure definition is detailed in [T128] section 9.1) and MUST be ignored.
    if ((max-p)>2 && 0x80==p[0] && 0x00==p[1])
        return true ;

    rdp     = INstance->context->rdp ;
    ss.size = (int)(max-p) ;
    ss.p    = p ;
    ss.data = p ;
    s       = &ss ;

    if (MCS_GLOBAL_CHANNEL_ID != chan)
    {
        // This is no longer used. Chan data processed in librdp.c
    }
    else
    {
        rdp_read_share_control_header(s, &pduLength, &pduType, &pduSource);

        rdp->settings->pdu_source = pduSource;

        switch (pduType)
        {
        case PDU_TYPE_DATA:
            if (!rdp_recv_data_pdu(rdp, s))
            {
                if (warning) printf("WARNING: play_response_slow: rdp_recv_data_pdu failed\n") ;
                return false;
            }
            break;

        case PDU_TYPE_DEACTIVATE_ALL:
            {
                uint16 lengthSourceDescriptor ;
                if (stream_get_left(s) > 0)
                {
                    stream_read_uint32(s, rdp->settings->share_id); /* shareId (4 bytes) */
                    stream_read_uint16(s, lengthSourceDescriptor); /* lengthSourceDescriptor (2 bytes) */
                    stream_seek(s, lengthSourceDescriptor); /* sourceDescriptor (should be 0x00) */
                }
            }
            break;

        case PDU_TYPE_SERVER_REDIRECTION:
            rdp_recv_enhanced_security_redirection_packet(rdp, s);
            break;

        case PDU_TYPE_DEMAND_ACTIVE:
            {
                uint16_t lengthSourceDescriptor, lengthCombinedCapabilities, numberCapabilities ;
                rdp->settings->pdu_source = pduSource;
                stream_read_uint32(s, rdp->settings->share_id); /* shareId (4 bytes) */
                stream_read_uint16(s, lengthSourceDescriptor); /* lengthSourceDescriptor (2 bytes) */
                stream_read_uint16(s, lengthCombinedCapabilities); /* lengthCombinedCapabilities (2 bytes) */
                stream_seek(s, lengthSourceDescriptor); /* sourceDescriptor */
                stream_read_uint16(s, numberCapabilities); /* numberCapabilities (2 bytes) */
                stream_seek(s, 2); /* pad2Octets (2 bytes) */

                /* capabilitySets */
                if (!rdp_read_capability_sets(s, rdp->settings, numberCapabilities))
                {
                    printf("rdp_read_capability_sets failed\n");
                    return false;
                }
                rdp->update->secondary->glyph_v2 = (rdp->settings->glyphSupportLevel > GLYPH_SUPPORT_FULL) ? true : false;
            }
            break;

        default:
            printf("incorrect PDU type: 0x%04X\n", pduType);
            break;
        }
    }

    return true;
}


int play_response_fast(uint8_t *p, uint8_t *max, uint8_t header)
{
    struct rdp_rdp *rdp = INstance->context->rdp ;
    STREAM s ;
    s.size = (int)(max-p) ;
    s.p    = p ;
    s.data = p ;
    rdp->fastpath->encryptionFlags = (header & 0xC0) >> 6;
    rdp->fastpath->numberEvents = (header & 0x3C) >> 2;
    return fastpath_recv_updates(rdp->fastpath, &s);
}


int play_response_decompress(uint8_t **p2p, uint8_t **p2max, int flags)
{
    int       rlen ;
    uint8_t *new_p = SE_decompress_rdp(INstance->context->rdp, *p2p, (int)((*p2max)-(*p2p)), flags, &rlen) ;
    if (NULL==new_p)
    {
        printf("WARNING: play_response_decompress: SE_decompress_rdp failed\n") ;
        return false ;
    }
    *p2p   = new_p ;
    *p2max = new_p + rlen ;
    return true ;
}


int play_request_decompress(uint8_t **p2p, uint8_t **p2max, int flags)
{
    int       rlen ;
    uint8_t *new_p = SE_decompress_rdp(&requestRdp, *p2p, (int)((*p2max)-(*p2p)), flags, &rlen) ;
    if (NULL==new_p)
    {
        printf("WARNING: play_request_decompress: SE_decompress_rdp failed\n") ;
        return false ;
    }
    *p2p   = new_p ;
    *p2max = new_p + rlen ;
    return true ;
}


void play_quit()
{
    exit(0) ;
}


static int    cursor_visable = 0 ;
static int    cx = 0, cy = 0 ;
static int    play_need_init = 1 ;
typedef struct play_cur
{
    struct play_cur *next ;
    Cursor           cursor ;
    uint8_t         *data ;
    Pixmap           pix ;
    Pixmap           mask ;
    int              hx ;
    int              hy ;
    int              wx ;
    int              wy ;
} play_cur ;
play_cur *px_cursors = 0 ;
play_cur *active     = 0 ;

static Pixmap play_pixmap(xfInfo *xfi)
{
    static Pixmap pix ;
    static int    init = 1 ;
    if (init)
    {
        pix  = XCreatePixmap(xfi->display, xfi->drawable, 32, 32, xfi->depth) ;
        init = 0 ;
    }
    return pix ;
}


static GC get_my_gc(xfInfo *xfi)
{
    static int init = 1 ;
    static GC my_gc ;
    if (init)
    {
        my_gc = XCreateGC(xfi->display, xfi->primary, 0, NULL) ;
        XSetFunction(xfi->display, my_gc, GXcopy) ;
        init = 0 ;
    }
    return my_gc ;
}


static void undraw_cursor(xfInfo *xfi)
{
    if (cursor_visable && do_pointer && active)
    {
        GC my_gc = get_my_gc(xfi) ;
        XSetFunction(xfi->display, my_gc, GXcopy) ;
        XCopyArea(xfi->display, play_pixmap(xfi), xfi->primary,  my_gc, 0,0, 32,32, cx-active->hx,cy-active->hy) ;
        XCopyArea(xfi->display, play_pixmap(xfi), xfi->drawable, my_gc, 0,0, 32,32, cx-active->hx,cy-active->hy) ;
        cursor_visable = 0 ;
    }
}


static void draw_cursor(xfInfo *xfi)
{
    if (!cursor_visable && do_pointer && active)
    {
        int   sx = cx-active->hx ; // Starting X co-ord
        int   sy = cy-active->hy ; // Starting Y co-ord
        GC my_gc = get_my_gc(xfi) ;
        XSetFunction(xfi->display, my_gc, GXcopy) ;
        XCopyArea(xfi->display, xfi->drawable,  play_pixmap(xfi), my_gc, sx,sy, 32,32, 0,0) ;

        XSetFunction(  xfi->display, my_gc, GXand) ;
        XSetBackground(xfi->display, my_gc, ~0UL) ;
        XSetForeground(xfi->display, my_gc, 0UL) ;
        XCopyPlane(xfi->display,
                   active->mask,    // src
                   xfi->primary,    // dst
                   my_gc,
                   0,0,                         // src x,y
                   active->wx,active->wy,       // width,height
                   sx,sy,                       // dst x,y
                   1L) ; //Plane

        XSetFunction(xfi->display, my_gc, GXor) ;
        XCopyArea(xfi->display, active->pix,   xfi->primary, my_gc,  0,0,  active->wx,active->wy, sx,sy) ;
        XSetFunction(xfi->display, my_gc, GXcopy) ;
        XCopyArea(xfi->display, xfi->primary, xfi->drawable, my_gc, sx,sy, active->wx,active->wy, sx,sy) ;

        cursor_visable = 1 ;
    }
}


// Simple routine to close/free the video output, called by on_exit
static void playOnExit(int ev, void *ptr)
{
    void PlayVidFree(void *) ;
    PlayVidFree(ptr) ;
}


static void out2vid(xfInfo *xfi)
{
    extern const struct timeval *play_timeval ; // From librdp for packet timestamp (video timing)
    void *PlayVidAlloc(const char *fname, int width, int height) ;
    int write_frame(void *, const XImage *) ;
    static int need_init = 1 ;
    static void *hdl     = 0 ;
    static size_t t_sec  = 0 ;
    static size_t t_off  = 0 ;
    static size_t last_f = 0 ;
    extern const char *play_out_file ; // FIXME: this should not be a global
    size_t frame ;
    if (!xfi) return ;
    if (need_init) {
        if (play_out_file && play_timeval) {
            hdl = PlayVidAlloc(play_out_file, xfi->width, xfi->height) ;
            if (hdl) on_exit(playOnExit, hdl) ;
            t_sec = play_timeval->tv_sec ;
            t_off = play_timeval->tv_usec*25/1000000 ;
        }
        need_init = 0 ;
    }
    if (!hdl) return ;
    frame = (play_timeval->tv_sec-t_sec)*25 + (play_timeval->tv_usec*25/1000000) - t_off ;
    if (frame>last_f) {
        XImage *im = XGetImage(xfi->display, xfi->primary,
                               0,0, xfi->width, xfi->height,
                               ~0,ZPixmap) ;
        if (im) {
            while (frame>last_f) {
                write_frame(hdl, im) ;
                ++last_f ;
            }
            XDestroyImage(im) ;
        }
    }
}

static void update_cursor(xfInfo *xfi, int x, int y)
{
    if (xfi) out2vid(xfi) ;
    undraw_cursor(xfi) ;
    cx = x ;
    cy = y ;
    draw_cursor(xfi) ;
}

static void play_set_pixmap(Pixmap pix, rdpPointer *pointer, xfInfo *xfi, Pixmap mask)
{
    // Based on freerdp_alpha_cursor_convert in libfreerdp-codec/color.c
    int xpixel;
    int apixel;
    int i, j, jj;
    int        width = pointer->width ;
    int       height = pointer->height ;
    int          bpp = pointer->xorBpp ;
    HCLRCONV clrconv = xfi->clrconv ;
    uint8   *xorMask = pointer->xorMaskData ;
    uint8   *andMask = pointer->andMaskData ;
    GC         my_gc = get_my_gc(xfi) ;

    XSetFunction(xfi->display, my_gc, GXcopy) ;

    for (j = 0; j < height; j++)
    {
        jj = (bpp == 1) ? j : (height - 1) - j;
        for (i = 0; i < width; i++)
        {
            xpixel = freerdp_get_pixel(xorMask, i, jj, width, height, bpp);
            xpixel = freerdp_color_convert_rgb(xpixel, bpp, 32, clrconv);
            apixel = freerdp_get_pixel(andMask, i, jj, width, height, 1);

            if (apixel != 0)
            {
                // Transparent! Clear both.
                XSetFunction(xfi->display, my_gc, GXclear) ;
                XDrawPoint(xfi->display, mask, my_gc, i, j) ;
                XDrawPoint(xfi->display, pix, my_gc, i, j) ;
            }
            else
            {
                // Foreground. Set the mask, copy pixel into bitmap
                XSetFunction(xfi->display, my_gc, GXset) ;
                XDrawPoint(xfi->display, mask, my_gc, i, j) ;
                XSetFunction(xfi->display, my_gc, GXcopy) ;
                XSetForeground(xfi->display, my_gc, xpixel) ;
                XDrawPoint(xfi->display, pix, my_gc, i, j) ;
            }
        }
    }
}

void play_new_pointer(rdpContext *context, rdpPointer *pointer, Cursor cursor)
{
    xfInfo   *xfi = ((xfContext*)context)->xfi ;
    play_cur   *c = (play_cur *)malloc(sizeof(play_cur)) ;
    if (!c) return ;
    c->next       = px_cursors ;
    c->cursor     = cursor ;
    c->pix        = XCreatePixmap(xfi->display, xfi->drawable, pointer->width, pointer->height, xfi->depth) ;
    c->mask       = XCreatePixmap(xfi->display, xfi->drawable, pointer->width, pointer->height, xfi->depth) ;
    c->hx         = pointer->xPos ;
    c->hy         = pointer->yPos ;
    c->wx         = pointer->width ;
    c->wy         = pointer->height ;
    px_cursors    = c ;
    play_set_pixmap(c->pix, pointer, xfi, c->mask) ;
}
void play_set_pointer(rdpContext *context, Cursor cursor)
{
    xfInfo   *xfi = ((xfContext*)context)->xfi ;
    play_cur *ii ;
    undraw_cursor(xfi) ;
    active = 0 ;
    for (ii=px_cursors ; ii ; ii=ii->next)
        if (ii->cursor == cursor)
        {
            active = ii ;
            break ;
        }
    draw_cursor(xfi) ;
}
void play_del_pointer(rdpContext *context, Cursor cursor)
{
    xfInfo   *xfi = ((xfContext*)context)->xfi ;
    play_cur *ii, *last ;
    if (active && active->cursor==cursor)
    {
        if (xfi) undraw_cursor(xfi) ;
        active = 0 ;
    }
    for (last=0,ii=px_cursors ; ii ; ii=ii->next)
    {
        if (ii->cursor==cursor)
        {
            if (last) last->next = ii->next ;
            else      px_cursors = ii->next ;
            XFreePixmap(xfi->display, ii->pix) ;
            free(ii) ;
            break ;
        }
        last = ii ;
    }
}


void play_cursor(int x, int y)
{
    xfInfo   *xfi = ((xfContext*)INstance->context)->xfi ;
    if ( (!xfi) || (!xfi->display) ) return ;
    update_cursor(xfi, x, y) ;
}


// Locking.
static pthread_mutex_t *get_mx()
{
    static pthread_mutex_t mx ;
    static init = 1 ;
    if (init)
    {
        pthread_mutex_init(&mx, 0) ;
        init = 0 ;
    }
    return &mx ;
}
void play_mx_lock()
{
    pthread_mutex_lock(get_mx()) ;
}
void play_mx_unlock()
{
    pthread_mutex_unlock(get_mx()) ;
}


// For info on raster operaions, see:
// http://msdn.microsoft.com/en-us/library/windows/desktop/dd145130%28v=vs.85%29.aspx


void play_do_Xevents()
{
    // Based on xf_event_process in xf_event.c
    static int  NeedInit = 1 ;
    static Atom WM_PROTOCOLS, WM_DELETE_WINDOW ;
    boolean xf_event_MapNotify(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_UnmapNotify(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_ConfigureNotify(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_Expose(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_PropertyNotify(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_VisibilityNotify(xfInfo* xfi, XEvent* event, boolean app) ;
 // boolean xf_event_FocusIn(xfInfo* xfi, XEvent* event, boolean app) ;
 // boolean xf_event_FocusOut(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_EnterNotify(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_LeaveNotify(xfInfo* xfi, XEvent* event, boolean app) ;
    boolean xf_event_MappingNotify(xfInfo* xfi, XEvent* event, boolean app) ;

    XEvent xevent ;
    KeySym keysym ;
    char      str[256] ;
    xfInfo   *xfi = ((xfContext*)INstance->context)->xfi ;

    if ( (!xfi) || (!xfi->display) ) return ;

    play_mx_lock() ;
    while (XPending(xfi->display))
    {
        if (NeedInit)
        {
            WM_PROTOCOLS     = XInternAtom(xfi->display, "WM_PROTOCOLS", 0) ;
            WM_DELETE_WINDOW = XInternAtom(xfi->display, "WM_DELETE_WINDOW", 0) ;
            NeedInit         = 0 ;
        }

        memset(&xevent, 0, sizeof(xevent)) ;
        XNextEvent(xfi->display, &xevent) ;

        switch (xevent.type)
        {

        case Expose:
   //       xf_event_Expose(xfi, &xevent, xfi->remote_app) ;
            break ;

        case VisibilityNotify:
            xf_event_VisibilityNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        case MotionNotify:
        case ButtonPress:
        case ButtonRelease:
            break ;

        case KeyPress:
            if (0 < XLookupString(&xevent.xkey, str, sizeof(str), &keysym, NULL))
            {
            //  printf("Keys: %d %d %d\n", (int)str[0], (int)str[1], (int)str[2]) ;
                if (' '==str[0]) play_paused = 1 - play_paused ;
                if ('Q'==str[0]) play_quit() ;
                // FIXME: Support more keypress options
            }
            break ;

        case KeyRelease:
            break ;

        case FocusIn:
         // xf_event_FocusIn(xfi, &xevent, xfi->remote_app) ;
            break ;

        case FocusOut:
         // xf_event_FocusOut(xfi, &xevent, xfi->remote_app) ;
            break ;

        case EnterNotify:
            xf_event_EnterNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        case LeaveNotify:
            xf_event_LeaveNotify(xfi, &xevent, xfi->remote_app);
            break;

        case NoExpose:
        case GraphicsExpose:
            break;

        case ConfigureNotify:
            xf_event_ConfigureNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        case MapNotify:
            xf_event_MapNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        case UnmapNotify:
            xf_event_UnmapNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        case ReparentNotify:
            break ;

        case MappingNotify:
            xf_event_MappingNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        case ClientMessage:
            if ( (WM_PROTOCOLS     == xevent.xclient.message_type) &&
                 (WM_DELETE_WINDOW == (Atom)xevent.xclient.data.l[0]) )
                play_quit() ;
            break ;

        case SelectionNotify:
        case SelectionRequest:
        case SelectionClear:
            break ;

        case PropertyNotify:
         // xf_event_PropertyNotify(xfi, &xevent, xfi->remote_app) ;
            break ;

        default:
         // printf("Event-%d\n", (int)xevent.type) ;
            break ;
        }
    }
    play_mx_unlock() ;
}


void play_MultiDstBlt(rdpContext *context, MULTI_DSTBLT_ORDER *m)
{
    int                 ii ;
    DSTBLT_ORDER        ord ;
    rdpPrimaryUpdate *prim = context->rdp->update->primary ;

    if (trace_ord)
    {
        printf("Order: MultiDstBlt:\n") ;
        printf("     nLeftRect: %8d\n", (int)m->nLeftRect) ;
        printf("      nTopRect: %8d\n", (int)m->nTopRect) ;
        printf("        nWidth: %8d\n", (int)m->nWidth) ;
        printf("       nHeight: %8d\n", (int)m->nHeight) ;
        printf("          bRop: %8d\n", (int)m->bRop) ;
        printf(" numRectangles: %8d\n", (int)m->numRectangles) ;
        printf("        cbData: %8d\n", (int)m->cbData) ;
        for (ii=0 ; ii<=m->numRectangles ; ++ii)
            printf("             %d: %dx%d + %dx%d\n", ii,
                   (int)m->rectangles[ii].left,
                   (int)m->rectangles[ii].top,
                   (int)m->rectangles[ii].width,
                   (int)m->rectangles[ii].height) ;
    }

    // Set up common paramaters for the order
    ord.bRop      = m->bRop ;

    // YES, this loop starts at 1. for N rects we have to use 1...N.
    // This is a bug in the parsing, and probably needs fixing
    // Loop over the rectangles, and call DstBlt
    for (ii=1 ; ii<=m->numRectangles ; ++ii)
    {
        DELTA_RECT *r = m->rectangles+ii ;
        ord.nLeftRect = r->left ;
        ord.nTopRect  = r->top ;
        ord.nWidth    = r->width ;
        ord.nHeight   = r->height ;
        IFCALL(prim->DstBlt, context, &ord) ;
    }
}


void play_MultiPatBlt(rdpContext *context, MULTI_PATBLT_ORDER *m)
{
    int                 ii ;
    PATBLT_ORDER        ord ;
    rdpPrimaryUpdate *prim = context->rdp->update->primary ;

    if (trace_ord)
    {
        printf("Order: MultiPatBlt:\n") ;
        printf("     nLeftRect: %8d\n", (int)m->nLeftRect) ;
        printf("      nTopRect: %8d\n", (int)m->nTopRect) ;
        printf("        nWidth: %8d\n", (int)m->nWidth) ;
        printf("       nHeight: %8d\n", (int)m->nHeight) ;
        printf("          bRop: %8d\n", (int)m->bRop) ;
        printf("     backColor: %8x\n", (int)m->backColor) ;
        printf("     foreColor: %8x\n", (int)m->foreColor) ;
        printf(" numRectangles: %8d\n", (int)m->numRectangles) ;
        printf("        cbData: %8d\n", (int)m->cbData) ;
        for (ii=0 ; ii<=m->numRectangles ; ++ii)
            printf("             %d: %dx%d + %dx%d\n", ii,
                   (int)m->rectangles[ii].left,
                   (int)m->rectangles[ii].top,
                   (int)m->rectangles[ii].width,
                   (int)m->rectangles[ii].height) ;
    }

    // Set up common paramaters for the order
    ord.bRop      = m->bRop ;
    ord.backColor = m->backColor ;
    ord.foreColor = m->foreColor ;
    ord.brush     = m->brush ;

    // YES, this loop starts at 1. for N rects we have to use 1...N.
    // This is a bug in the parsing, and probably needs fixing
    // Loop over the rectangles, and call PatBlt
    for (ii=1 ; ii<=m->numRectangles ; ++ii)
    {
        DELTA_RECT *r = m->rectangles+ii ;
        ord.nLeftRect = r->left ;
        ord.nTopRect  = r->top ;
        ord.nWidth    = r->width ;
        ord.nHeight   = r->height ;
        IFCALL(prim->PatBlt, context, &ord) ;
    }
}


void play_MultiScrBlt(rdpContext *context, MULTI_SCRBLT_ORDER* m)
{
    int                 ii ;
    SCRBLT_ORDER       ord ;
    rdpPrimaryUpdate *prim = context->rdp->update->primary ;

    if (trace_ord)
    {
        printf("Order: MultiScrBlt:\n") ;
        printf("     nLeftRect: %8d\n", (int)m->nLeftRect) ;
        printf("      nTopRect: %8d\n", (int)m->nTopRect) ;
        printf("        nWidth: %8d\n", (int)m->nWidth) ;
        printf("       nHeight: %8d\n", (int)m->nHeight) ;
        printf("          bRop: %8d\n", (int)m->bRop) ;
        printf("         nXSrc: %8d\n", (int)m->nXSrc) ;
        printf("         nYSrc: %8d\n", (int)m->nYSrc) ;
        printf(" numRectangles: %8d\n", (int)m->numRectangles) ;
        printf("        cbData: %8d\n", (int)m->cbData) ;
        for (ii=0 ; ii<=m->numRectangles ; ++ii)
            printf("             %d: %dx%d + %dx%d\n", ii,
                   (int)m->rectangles[ii].left,
                   (int)m->rectangles[ii].top,
                   (int)m->rectangles[ii].width,
                   (int)m->rectangles[ii].height) ;
    }

    // Set up common paramaters for the order
    ord.bRop = m->bRop ;

    // YES, this loop starts at 1. for N rects we have to use 1...N.
    // This is a bug in the parsing, and probably needs fixing
    // Loop over the rectangles, and call ScrBlt
    for (ii=1 ; ii<=m->numRectangles ; ++ii)
    {
        DELTA_RECT *r = m->rectangles+ii ;
        ord.nLeftRect = r->left ;
        ord.nTopRect  = r->top ;
        ord.nWidth    = r->width ;
        ord.nHeight   = r->height ;
        ord.nXSrc     = r->left - m->nLeftRect + m->nXSrc ;
        ord.nYSrc     = r->top  - m->nTopRect  + m->nYSrc ;
        IFCALL(prim->ScrBlt, context, &ord) ;
    }
}


// Note about primary and drawable.
//   xfi->primary    Pixmap that you should use to draw on.
//   xfi->drawable   Window. This is what is displayed.
// Draw on primary and copy it to the window. This is so we can repair windows after
// exposure events etc. by copying from primary to drawable.
//
void play_SaveBitmap(rdpContext* context, SAVE_BITMAP_ORDER* save_bitmap)
{
    // This should really be implemented as a 480x480 bitmap. See
    // http://msdn.microsoft.com/en-us/library/cc241861.aspx
    typedef struct sb
    {
        struct sb *next ;
        uint32     pos ;
        uint32     width ;
        uint32     height ;
        Pixmap     pix ;
    } sb ;
    static sb *save = 0 ; // List of current saved bitmaps - FIXME: Should be part of context?
    sb        *ii ;
    xfInfo   *xfi = ((xfContext*)context)->xfi ;
    GC      my_gc = get_my_gc(xfi) ;
    int     width ;
    int    height ;

    if (trace_ord)
    {
        printf("Order: SaveBitmap:\n") ;
        printf("  savedBitmapPosition: %8d\n", (int)save_bitmap->savedBitmapPosition) ;
        printf("            nLeftRect: %8d\n", (int)save_bitmap->nLeftRect) ;
        printf("             nTopRect: %8d\n", (int)save_bitmap->nTopRect) ;
        printf("           nRightRect: %8d\n", (int)save_bitmap->nRightRect) ;
        printf("          nBottomRect: %8d\n", (int)save_bitmap->nBottomRect) ;
        printf("            operation: %8d (%s)\n", (int)save_bitmap->operation, save_bitmap->operation?"Restore":"Save") ;
    }

    width  = 1 + save_bitmap->nRightRect  - save_bitmap->nLeftRect ;
    height = 1 + save_bitmap->nBottomRect - save_bitmap->nTopRect ;

    if ( (width  <= 0) ||
         (height <= 0) )
    {
        if (warning)
            printf("WARNING: play_SaveBitmap: Bad pars\n") ;
        return ;
    }

    // Find this offset, if we have it.
    for (ii=save ; ii ; ii=ii->next)
        if (ii->pos == save_bitmap->savedBitmapPosition)
            break ;

    XSetFunction(xfi->display, my_gc, GXcopy) ;

    if (save_bitmap->operation)
    {
        // Restore
        if (!ii)
        {
            if (warning)
                printf("WARNING: play_SaveBitmap: Restore with no save!\n") ;
            return ;
        }
        if ( (width  != ii->width) ||
             (height != ii->height) )
        {
            if (warning)
                printf("WARNING: play_SaveBitmap: Bad shape on restore!\n") ;
            return ;
        }
        XCopyArea(xfi->display,
                  ii->pix,              // src drawable
                  xfi->primary,         // dest drawable
                  my_gc,
                  0,0,                  // src x,y
                  width,
                  height,
                  save_bitmap->nLeftRect, // dest-x
                  save_bitmap->nTopRect   // dest-y
                 ) ;
        XCopyArea(xfi->display,
                  ii->pix,              // src drawable
                  xfi->drawable,        // dest drawable
                  my_gc,
                  0,0,                  // src x,y
                  width,
                  height,
                  save_bitmap->nLeftRect, // dest-x
                  save_bitmap->nTopRect   // dest-y
                 ) ;
    }
    else
    {
        // Save
        if (!ii)
        {
            ii = malloc(sizeof(sb)) ;
            if (!ii) return ;
            ii->next = save ;
            save     = ii ;
        }
        else
            XFreePixmap(xfi->display, ii->pix) ;

        ii->pos    = save_bitmap->savedBitmapPosition ;
        ii->width  = width ;
        ii->height = height ;
        ii->pix    = XCreatePixmap(xfi->display, xfi->drawable, ii->width, ii->height, xfi->depth) ;
        XCopyArea(xfi->display,
                  xfi->primary,         // src drawable
                  ii->pix,              // dest drawable
                  my_gc,
                  save_bitmap->nLeftRect, // src-x
                  save_bitmap->nTopRect,  // src-y
                  width,
                  height,
                  0,0) ;                // dest x,y
    }
}

