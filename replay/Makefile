all: rdp_replay

# May need to change this:
TOOLS=../tools

#=-=#=-=#=-=#

FREE_HOME=../libfree_rdp
FREERDP_INC_DIR =-I${FREE_HOME}/include

debug: all
debug: CPPFLAGS+=-g -ggdb

FREERDP_FLAGS =-DWITH_XINERAMA -DWITH_XCURSOR -DWITH_XV -DWITH_XEXT -DEXT_PATH=\"/usr/lib/freerdp/extensions\"
CPPFLAGS     += ${FREERDP_INC_DIR} -I. ${FREERDP_FLAGS}
LIBS         += -lXrandr -lXcursor -lXinerama -lXv -lxkbfile -lXext -lX11 -lpcap -lpthread -ldl
LIBS         += -lasound

# Stuff from libfreerdp-cache O_=Orig, C_=Changed
O_CACHE  = brush.c cache.c glyph.c nine_grid.c offscreen.c palette.c pointer.c
N_CACHE  = bitmap.c
EXT_OBJ += $(addprefix ${FREE_HOME}/libfreerdp-cache/*/*dir/,$(O_CACHE:=.o))
OUR_OBJ += $(N_CACHE:.c=.o)

# Stuff from libfreerdp-core O_=Orig, C_=Changed
O_CORE = activation.c capabilities.c certificate.c channel.c errinfo.c\
	extension.c freerdp.c graphics.c info.c input.c license.c listener.c\
	mcs.c nego.c peer.c redirection.c rpch.c security.c settings.c\
	surface.c timezone.c tpdu.c tpkt.c transport.c tsg.c update.c window.c
C_CORE = connection.c fastpath.c gcc.c mppc.c orders.c rdp.c tcp.c
EXT_OBJ += $(addprefix ${FREE_HOME}/libfreerdp-core/*/*dir/,$(O_CORE:=.o))
OUR_OBJ += $(C_CORE:.c=.o)
CPPFLAGS += -I${FREE_HOME} -I${FREE_HOME}/libfreerdp-core

# Unchanged libraries from libfreerdp: (we use the objects to simplify library problems)
EXT_OBJ += ${FREE_HOME}/libfreerdp-auth/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-channels/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-codec/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-crypto/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-gdi/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-locale/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-rail/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/libfreerdp-utils/*/*dir/*.o
EXT_OBJ += ${FREE_HOME}/channels/rdpsnd/alsa/CMakeFiles/rdpsnd_alsa.dir/rdpsnd_alsa.c.o

# Client code O_=Orig, C_=Changed
O_CLIENT = xf_cliprdr.c xf_keyboard.c xf_monitor.c xf_rail.c xf_tsmf.c
C_CLIENT = xfreerdp.c xf_event.c xf_gdi.c xf_graphics.c xf_window.c
EXT_OBJ += $(addprefix ${FREE_HOME}/client/X11/*/*dir/,$(O_CLIENT:=.o))
OUR_OBJ += $(C_CLIENT:.c=.o)
CPPFLAGS += -I${FREE_HOME}/client/X11
CPPFLAGS += -I${FREE_HOME}/channels/rdpsnd

# Things we need from tools
CXX_SOURCE += ${TOOLS}/ssl_decrypt.C ${TOOLS}/buffer.C ${TOOLS}/pcap_delay.C ${TOOLS}/pkt_pro.C
CPPFLAGS   += -I${TOOLS}
LIBS       += -lcrypto /usr/lib/x86_64-linux-gnu/libssl.a


# New programs. Main items, if you like.
#
OUR_OBJ    += librdp.o play_vid.o chan_rdpsnd.o chan_rdpdr.o
LIBS       += -lavformat -lavcodec -lavutil
CXX_SOURCE += rdp_replay.C

rdp_replay: ${CXX_SOURCE} ${OUR_OBJ} ${EXT_OBJ}
	g++ ${CPPFLAGS} -o $@ ${CXX_SOURCE} ${OUR_OBJ} ${EXT_OBJ} ${LD_FLAGS} ${LIBS}

clean:
	rm -rf ${OUR_OBJ} rdp_replay
