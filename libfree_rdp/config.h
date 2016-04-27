#ifndef __CONFIG_H
#define __CONFIG_H

#define FREERDP_VERSION "1.0"
#define FREERDP_VERSION_FULL "1.0.1"
#define FREERDP_VERSION_MAJOR 1
#define FREERDP_VERSION_MINOR 0
#define FREERDP_VERSION_REVISION 1

#define FREERDP_DATA_PATH "/usr/local/share/freerdp"
#define FREERDP_PLUGIN_PATH "/usr/local/lib/x86_64-linux-gnu/freerdp"
#define FREERDP_KEYMAP_PATH "/usr/local/share/freerdp/keymaps"

/* Include files */
#define HAVE_SYS_PARAM_H
#define HAVE_SYS_SOCKET_H
#define HAVE_NETDB_H
#define HAVE_FCNTL_H
#define HAVE_UNISTD_H
#define HAVE_LIMITS_H
#define HAVE_STDINT_H
#define HAVE_STDBOOL_H
#define HAVE_INTTYPES_H

#define HAVE_TM_GMTOFF

/* Endian */
/* #undef BIG_ENDIAN */

/* Options */
/* #undef WITH_DEBUG_TRANSPORT */
/* #undef WITH_DEBUG_CHANNELS */
/* #undef WITH_DEBUG_SVC */
/* #undef WITH_DEBUG_DVC */
/* #undef WITH_DEBUG_KBD */
/* #undef WITH_DEBUG_NLA */
/* #undef WITH_DEBUG_NEGO */
/* #undef WITH_DEBUG_CERTIFICATE */
/* #undef WITH_DEBUG_LICENSE */
/* #undef WITH_DEBUG_GDI */
/* #undef WITH_DEBUG_ASSERT */
/* #undef WITH_DEBUG_RFX */
/* #undef WITH_PROFILER */
#define WITH_SSE2
/* #undef WITH_SSE2_TARGET */
/* #undef WITH_NEON */
/* #undef WITH_DEBUG_X11 */
/* #undef WITH_DEBUG_X11_CLIPRDR */
/* #undef WITH_DEBUG_X11_LOCAL_MOVESIZE */
/* #undef WITH_DEBUG_RAIL */
/* #undef WITH_DEBUG_XV */
/* #undef WITH_DEBUG_SCARD */
/* #undef WITH_DEBUG_ORDERS */
/* #undef WITH_DEBUG_REDIR */
/* #undef WITH_DEBUG_CLIPRDR */
/* #undef WITH_DEBUG_WND */
/* #undef WITH_DEBUG_RPCH */
/* #undef WITH_DEBUG_TSG */
#endif
