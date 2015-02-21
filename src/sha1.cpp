/* sha1.cpp

Copyright (c) 2005 Michael D. Leonhard

http://tamale.net/

This file is licensed under the terms described in the
accompanying LICENSE file.
*/

#include <cstring>
#include <cassert>

#include "conf.h"
#include "sha1.h"
#include "sha1_loc.h"

namespace sha1 {
    // Constructor *******************************************************
    sha1_t::sha1_t() {
        initialise();
    }

    // Constructor *******************************************************
    sha1_t::sha1_t(const char* input, const unsigned int input_length, void* signature_) {
        initialise();

        process(input, input_length);

        finish(signature);
    }

    // process ***********************************************************
    void sha1_t::process_block() {
        if (unprocessedBytes == sha1::BLOCK_SIZE) {
            int t;
            unsigned int a, b, c, d, e, K, f, W[80];

            // starting values
            a = H0;
            b = H1;
            c = H2;
            d = H3;
            e = H4;

            // copy and expand the message block
            for (t = 0; t < 16; t++)
                W[t] = (bytes[t * 4]     << 24)
                     + (bytes[t * 4 + 1] << 16)
                     + (bytes[t * 4 + 2] << 8)
                     +  bytes[t * 4 + 3];

            for (; t < 80; t++)
                W[t] = cyclic_left_rotate(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);

            /* main loop */
            unsigned int temp;
            for (t = 0; t < 80; t++) {
                if (t < 20) {
                    K = 0x5a827999;
                    f = (b & c) | ((b ^ 0xFFFFFFFF) & d); //TODO: try using ~
                } else if (t < 40) {
                    K = 0x6ed9eba1;
                    f = b ^ c ^ d;
                } else if (t < 60) {
                    K = 0x8f1bbcdc;
                    f = (b & c) | (b & d) | (c & d);
                } else {
                    K = 0xca62c1d6;
                    f = b ^ c ^ d;
                }

                temp = cyclic_left_rotate(a, 5) + f + e + W[t] + K;
                e = d;
                d = c;
                c = cyclic_left_rotate(b, 30);
                b = a;
                a = temp;
            }

            /* add variables */
            H0 += a;
            H1 += b;
            H2 += c;
            H3 += d;
            H4 += e;

            /* all bytes have been processed */
            unprocessedBytes = 0;
        }
    }

    // addBytes **********************************************************
    void sha1_t::process(const char* input, int input_length) {
        if (!finished) {
            if (input_length <= 0)
                return;

            // add these bytes to the running total
            size += input_length;

            // repeat until all data is processed
            while (input_length > 0) {
                // number of bytes required to complete block
                int needed = sha1::BLOCK_SIZE - unprocessedBytes;
                assert(needed > 0);

                // number of bytes to copy (use smaller of two)
                int toCopy = (input_length < needed) ? input_length : needed;

                // Copy the bytes
                memcpy(bytes + unprocessedBytes, input, toCopy);

                // Bytes have been copied
                input_length -= toCopy;
                input += toCopy;
                unprocessedBytes += toCopy;

                // there is a full block
                if (unprocessedBytes == sha1::BLOCK_SIZE)
                    process_block();
            }
        }
    }

    // digest ************************************************************
    void sha1_t::finish(void* signature_) {
        if (!finished) {
            // save the message size
            unsigned int totalBitsL = size << 3;
            unsigned int totalBitsH = size >> 29;

            // add 0x80 to the message
            process("\x80", 1);

            unsigned char footer[sha1::BLOCK_SIZE] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            // block has no room for 8-byte filesize, so finish it
            if( unprocessedBytes > 56 )
                process((char*)footer, sha1::BLOCK_SIZE - unprocessedBytes);

            assert( unprocessedBytes <= 56 );

            // how many zeros do we need
            int neededZeros = 56 - unprocessedBytes;

            // store file size (in bits) in big-endian format
            sha1::make_big_endian_uint32( footer + neededZeros    , totalBitsH );
            sha1::make_big_endian_uint32( footer + neededZeros + 4, totalBitsL );

            // finish the final block
            process((char*)footer, neededZeros + 8);

            // copy the digest bytes
            sha1::make_big_endian_uint32(signature,      H0);
            sha1::make_big_endian_uint32(signature + 4,  H1);
            sha1::make_big_endian_uint32(signature + 8,  H2);
            sha1::make_big_endian_uint32(signature + 12, H3);
            sha1::make_big_endian_uint32(signature + 16, H4);

            // return the digest
            if (signature_ != NULL) {
                memcpy(signature_, signature, SHA1_SIZE);
            }

            sig_to_string(signature, str, SHA1_STRING_SIZE);

            finished = true;
        }
    }

   /*
     * get_sig
     *
     * DESCRIPTION:
     *
     * Retrieves the previously calculated signature from the SHA1 object.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - A 16 byte buffer that will contain the SHA1 signature.
     */
    void sha1_t::get_sig(void* signature_) {
        if (finished) {
            memcpy(signature_, signature, SHA1_SIZE);
        }
    }

    /*
     * get_string
     *
     * DESCRIPTION:
     *
     * Retrieves the previously calculated signature from the SHA1 object in
     * printable format.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * str_ - a string of characters which should be at least 41 bytes long
     * (2 characters per SHA1 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    void sha1_t::get_string(void* str_, const unsigned int str_len) {
        if (finished) {
            memcpy(str_, str, str_len);
        }
    }

    void sha1_t::initialise() {
        /*
         * ensures that unsigned int is 4 bytes on this platform, will need modifying
         * if we are to use on a different sized platform.
         */
        assert(SHA1_SIZE == 20);

        H0 = 0x67452301;
        H1 = 0xefcdab89;
        H2 = 0x98badcfe;
        H3 = 0x10325476;
        H4 = 0xc3d2e1f0;

        unprocessedBytes = 0;
        size = 0;

        finished = false;
    }

    /****************************** Exported Functions ******************************/

    /*
     * sig_to_string
     *
     * DESCRIPTION:
     *
     * Convert a SHA1 signature in a 20 byte buffer into a hexadecimal string
     * representation.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - a 20 byte buffer that contains the MD5 signature.
     *
     * str_ - a string of charactes which should be at least 41 bytes long (2
     * characters per SHA1 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    void sig_to_string(const void* signature_, char* str_, const int str_len) {
        unsigned char* sig_p;
        char* str_p;
        char* max_p;
        unsigned int high, low;

        str_p = str_;
        max_p = str_ + str_len;

        for (sig_p = (unsigned char*)signature_; sig_p < (unsigned char*)signature_ + SHA1_SIZE; sig_p++) {
            high = *sig_p / 16;
            low = *sig_p % 16;
            /* account for 2 chars */
            if (str_p + 1 >= max_p) {
                break;
            }
            *str_p++ = sha1::HEX_STRING[high];
            *str_p++ = sha1::HEX_STRING[low];
        }
        /* account for 2 chars */
        if (str_p < max_p) {
            *str_p++ = '\0';
        }
    }

    /*
     * sig_from_string
     *
     * DESCRIPTION:
     *
     * Convert a SHA1 signature from a hexadecimal string representation into
     * a 20 byte buffer.
     *
     * RETURNS:
     *
     * None.
     *
     * ARGUMENTS:
     *
     * signature_ - A 20 byte buffer that will contain the SHA1 signature.
     *
     * str_ - A string of charactes which _must_ be at least 40 bytes long (2
     * characters per SHA1 byte).
     */
    void sig_from_string(void* signature_, const char* str_) {
        unsigned char *sig_p;
        const char *str_p;
        char* hex;
        unsigned int high, low, val;

        hex = (char*)sha1::HEX_STRING;
        sig_p = static_cast<unsigned char*>(signature_);

        for (str_p = str_; str_p < str_ + SHA1_SIZE * 2; str_p += 2) {
            high = strchr(hex, *str_p) - hex;
            low = strchr(hex, *(str_p + 1)) - hex;
            val = high * 16 + low;
            *sig_p++ = val;
        }
    }
} // namespace sha1

