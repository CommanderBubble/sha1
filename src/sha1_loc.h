/*
 * Local defines for the md5 functions.
 *
 * $Id: md5_loc.h,v 1.5 2010-05-07 13:58:18 gray Exp $
 */

/*
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it is
 * identified as the "RSA Data Security, Inc. md5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Data Security,
 * Inc. md5 Message-Digest Algorithm" in all material mentioning or
 * referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either the
 * merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is" without
 * express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

#ifndef __SHA15_LOC_H__
#define __SHA1_LOC_H__

namespace sha1 {
    const char* HEX_STRING = "0123456789abcdef";    /* to convert to hex */
}
    /*
     * Define my endian-ness.  Could not do in a portable manner using the
     * include files -- grumble.
     */
    #if SHA1_BIG_ENDIAN

    /*
     * big endian - big is better
     */
    #define SHA1_SWAP(n) (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))

    #else

    /*
     * little endian
     */
    #define SHA1_SWAP(n) (n)

    #endif

#endif /* ! __SHA1_LOC_H__ */
