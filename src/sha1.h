/* sha1.h

Copyright (c) 2005 Michael D. Leonhard

http://tamale.net/

This file is licensed under the terms described in the
accompanying LICENSE file.
*/

#ifndef SHA1_HEADER

namespace SHA1 {
    class SHA1_t {
        public:
            SHA1_t();
            ~SHA1_t();

            void addBytes(const char*, int);
            unsigned char* getDigest();
        private:
            // utility methods
            unsigned int lrot(unsigned int, int);
            void storeBigEndianUint32(unsigned char*, unsigned int);

            // fields
            unsigned int H0, H1, H2, H3, H4;
            unsigned char bytes[64];
            int unprocessedBytes;
            size_t size;
            void process();
    };

    void hex_printer(unsigned char*, int);
    void hex_to_string(unsigned char*, char*, int);
} // namescpace SHA1

#define SHA1_HEADER
#endif
