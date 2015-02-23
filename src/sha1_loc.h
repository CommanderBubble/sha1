/*
 * Local defines for the md5 functions.
 *
 * $Id: md5_loc.h,v 1.5 2010-05-07 13:58:18 gray Exp $
 */

#ifndef __SHA1_LOC_H__
#define __SHA1_LOC_H__

namespace sha1 {
    /*
     * Function to perform the cyclic left rotation of blocks of data
     */
    inline unsigned int cyclic_left_rotate(unsigned int data, unsigned int shift_bits) {
        return (data << shift_bits) | (data >> (32 - shift_bits));
    }

    // Save a 32-bit unsigned integer to memory, in big-endian order
    inline void make_big_endian_uint32( unsigned char* byte, unsigned int num ) {
        byte[0] = (unsigned char)(num >> 24);
        byte[1] = (unsigned char)(num >> 16);
        byte[2] = (unsigned char)(num >> 8);
        byte[3] = (unsigned char)num;
    }

    const char* HEX_STRING = "0123456789abcdef";    /* to convert to hex */
}
#endif /* ! __SHA1_LOC_H__ */
