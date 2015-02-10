/* sha1.h

Copyright (c) 2005 Michael D. Leonhard

http://tamale.net/

This file is licensed under the terms described in the
accompanying LICENSE file.
*/

#ifndef SHA1_HEADER
typedef unsigned int Uint32;

class SHA1 {
	public:
	    SHA1();
	    ~SHA1();

		void addBytes(const char*, int);
		unsigned char* getDigest();

		// utility methods
		Uint32 lrot(Uint32, int);
		void storeBigEndianUint32(unsigned char*, Uint32);

	private:
		// fields
		Uint32 H0, H1, H2, H3, H4;
		unsigned char bytes[64];
		int unprocessedBytes;
		Uint32 size;
		void process();
};

extern void SHA1_hexPrinter(unsigned char*, int);
extern void SHA1_hexToString(unsigned char*, char*, int);

#define SHA1_HEADER
#endif
