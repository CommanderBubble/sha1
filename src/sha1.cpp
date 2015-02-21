#include <cstring>
#include <cassert>
#include <iostream>

#include "conf.h"
#include "sha1.h"
#include "sha1_loc.h"

namespace sha1 {
    // Constructor *******************************************************
    sha1_t::sha1_t() {
        initialise();
    }

    // Constructor *******************************************************
    sha1_t::sha1_t(const void* input, const unsigned int input_length, void* signature_) {
        initialise();

        process(input, input_length);

        finish(signature);
    }

    // addBytes **********************************************************
    void sha1_t::process(const void* input, int input_length) {
        if (!finished) {
            unsigned int processed = 0;

            //
            // If we have any data stored from a previous call to process then we use these
            // bytes first, and the new data is large enough to create a complete block then
            // we process these bytes first.
            //
            if (stored_size and input_length + stored_size >= sha1::BLOCK_SIZE) {
                unsigned char block[sha1::BLOCK_SIZE];
                memcpy(block, stored, stored_size);
                memcpy(block + stored_size, input, sha1::BLOCK_SIZE - stored_size);
                processed = sha1::BLOCK_SIZE - stored_size;
                stored_size = 0;
                process_block(block);
            }

            //
            // While there is enough data to create a complete block, process it.
            //
            while (processed + sha1::BLOCK_SIZE <= input_length) {
                process_block((unsigned char*)input + processed);
                processed += sha1::BLOCK_SIZE;
            }

            //
            // If there are any unprocessed bytes left over that do not create a complete block
            // then we store these bytes for processing next time.
            //
            if (processed < input_length) {
                memcpy(stored + stored_size, (char*)input + processed, input_length - processed);
                stored_size += input_length - processed;
            } else {
                stored_size = 0;
            }
        }
    }

    // digest ************************************************************
    void sha1_t::finish(void* signature_) {
        if (!finished) {
            // add these bytes to the running total
            if (message_length[0] + stored_size < message_length[0])
                message_length[1]++;
            message_length[0] += stored_size;

            // save the message size
            unsigned int totalBitsL = ((message_length[0] & 0x1FFFFFFF) << 3);
            unsigned int totalBitsH = (message_length[1] << 3) | ((message_length[0] & 0xE0000000) >> 29);

            // add 0x80 to the message
            process("\x80", 1);

            unsigned char footer[sha1::BLOCK_SIZE] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            // block has no room for 8-byte filesize, so finish it
            if( stored_size > 56 )
                process((char*)footer, sha1::BLOCK_SIZE - stored_size);

            assert( stored_size <= 56 );

            // how many zeros do we need
            int neededZeros = 56 - stored_size;

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

        stored_size = 0;
        message_length[0] = 0;
        message_length[1] = 0;

        finished = false;
    }

    // process ***********************************************************
    void sha1_t::process_block(const unsigned char* block) {
        // add these bytes to the running total
        if (message_length[0] + sha1::BLOCK_SIZE < message_length[0])
            message_length[1]++;
        message_length[0] += sha1::BLOCK_SIZE;

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
            W[t] = (block[t * 4]     << 24)
                 + (block[t * 4 + 1] << 16)
                 + (block[t * 4 + 2] << 8)
                 +  block[t * 4 + 3];

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
        stored_size = 0;
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
     * signature_ - a 20 byte buffer that contains the sha1 signature.
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

