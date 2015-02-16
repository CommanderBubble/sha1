/* sha1.h

Copyright (c) 2005 Michael D. Leonhard

http://tamale.net/

This file is licensed under the terms described in the
accompanying LICENSE file.
*/

#ifndef SHA1_HEADER

/*
 *
 *
 * currently doens't account for platforms where unsigned int isn't a 4 byte type
 *
 * this should be 20.
 *
 */
const unsigned int SHA1_SIZE = 5 * sizeof(unsigned int);

namespace sha1 {

    const char* HEX_STRING = "0123456789abcdef"; // to convert to hex

    class sha1_t {
        public:
            sha1_t();
            ~sha1_t();

            void addBytes(const char*, int);
            unsigned char* getDigest();
        private:
            // utility methods
            unsigned int lrot(unsigned int, int);
            void storeBigEndianUint32(unsigned char*, unsigned int);
            void process();

            // fields
            unsigned int H0, H1, H2, H3, H4;
            unsigned char bytes[64];
            int unprocessedBytes;
            size_t size;
    };

    void hex_printer(unsigned char*, int);
    void hex_to_string(unsigned char*, char*, int);

} // namescpace sha1

#define SHA1_HEADER
#endif
