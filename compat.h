/* 
 * compat.h
 * Compatibility definitions.
 *
 * Part of ksudo. Copyright 2012 Ben Morrow <ben@morrow.me.uk>.
 * Released under the 2-clause BSD licence.
 *
 * Requires config.h.
 */

#ifndef __compat_h__
#define __compat_h__

#ifdef HAVE_STRING_H
#  include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif

#ifndef HAVE_BZERO
#  define bzero(v, l) memset((v), 0, (l))
#endif

#endif
