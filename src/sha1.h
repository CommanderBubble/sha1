/* sha1.h

Copyright (c) 2005 Michael D. Leonhard

http://tamale.net/

This file is licensed under the terms described in the
accompanying LICENSE file.
*/

#ifndef SHA1_HEADER
#define SHA1_HEADER

/*
 *
 *
 * currently doens't account for platforms where unsigned int isn't a 4 byte type
 *
 * this should be 20.
 *
 */
const unsigned int SHA1_SIZE = (5 * sizeof(unsigned int));

namespace sha1 {


    const char* HEX_STRING = "0123456789abcdef"; // to convert to hex

    /*
     * The MD5 algorithm works on blocks of characters of 64 bytes.  This
     * is an internal value only and is not necessary for external use.
     */
    const unsigned int BLOCK_SIZE = 64;

    class sha1_t {
        public:
                        /*
             * sha1_t
             *
             * DESCRIPTION:
             *
             * Initialize structure containing state of MD5 computation. (RFC 1321,
             * 3.3: Step 3).  This is for progressive MD5 calculations only.  If
             * you have the complete string available, call it as below.
             * process should be called for each bunch of bytes and after the last
             * process call, finish should be called to get the signature.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * None.
             */
            sha1_t();

            /*
             * sha1_t
             *
             * DESCRIPTION:
             *
             * This function is used to calculate a SHA1 signature for a buffer of
             * bytes.  If you only have part of a buffer that you want to process
             * then sha1_t, process, and finish should be used.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * buffer - A buffer of bytes whose SHA1 signature we are calculating.
             *
             * buf_len - The length of the buffer.
             *
             * signature_ - A 20 byte buffer that will contain the MD5 signature.
             */
            sha1_t(const char* buffer, const unsigned int buf_len, void* signature_);

            void process(const char*, int);
            void finish(void* signature_ = NULL);
            unsigned char* getDigest();

        private:
            // utility methods
            void initialise();

            unsigned int lrot(unsigned int, int);
            void storeBigEndianUint32(unsigned char*, unsigned int);
            void process_block();

            // fields
            unsigned int H0;
            unsigned int H1;
            unsigned int H2;
            unsigned int H3;
            unsigned int H4;

            unsigned char bytes[64];
            int unprocessedBytes;
            size_t size;

            unsigned char signature[SHA1_SIZE];           /* stored signature */
            //char str[33];                       /* stored plain text hash */

            bool finished;
    };

    void hex_printer(unsigned char*, int);
    void hex_to_string(unsigned char*, char*, int);

} // namescpace sha1


#endif
