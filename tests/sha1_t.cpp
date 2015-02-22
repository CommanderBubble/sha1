#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <fcntl.h>
#include <vector>
#include <iostream>

#include "../src/sha1.h"

int run_tests() {
    int ret = 0;

	// these example text blocks are taken from RFC3174
    std::vector<std::pair<const char*, const char*> > tests;
    tests.push_back(std::pair<const char*, const char*>("abc","a9993e364706816aba3e25717850c26c9cd0d89d"));
    tests.push_back(std::pair<const char*, const char*>("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","84983e441c3bd26ebaae4aa1f95129e5e54670f1"));
    tests.push_back(std::pair<const char*, const char*>("a","34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
    tests.push_back(std::pair<const char*, const char*>("0123456701234567012345670123456701234567012345670123456701234567","dea356a2cddd90c7a7ecedc5ebb563934f460452"));

    tests.push_back(std::pair<const char*, const char*>("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0ea59bfe8787939816796610c73deb1c625e03ed"));

    std::vector<unsigned int> multiplier;
    multiplier.push_back(1);
    multiplier.push_back(1);
    multiplier.push_back(1000000);
    multiplier.push_back(10);
    multiplier.push_back(8388608);


    int passed = 0;
    int passed_h = 0;
    int passed_c = 0;

    unsigned char sig[SHA1_SIZE], sig2[SHA1_SIZE];
    char str[SHA1_STRING_SIZE];

    /* run our tests */
    for (unsigned int i = 0; i < tests.size(); i++) {
        bool passed_hash = 0;
        bool passed_convert = 0;

        sha1::sha1_t sha1;

        for (unsigned int j = 0; j < multiplier[i]; j++) {
            sha1.process(tests[i].first, strlen(tests[i].first));
        }

        sha1.finish(sig);

        /* convert from the sig to a string rep */
        sha1::sig_to_string(sig, str);
        if (strcmp(str, tests[i].second) == 0) {
            passed_hash = true;
            passed_h++;
        }

        /* convert from the string back into a MD5 signature */
        sha1::sig_from_string(sig2, str);
        if (memcmp(sig, sig2, SHA1_SIZE) == 0) {
            passed_convert = true;
            passed_c++;
        }

        if (passed_hash and passed_convert) {
            std::cout << "TEST " << i + 1 << " PASSED" << std::endl;
            passed++;
        } else {
            std::cout << "TEST " << i + 1 << " FAILED" << std::endl;
            std::cout << "Hash: " << str << std::endl;
        }
    }

    std::cout << std::endl << "*******************************" << std::endl
              << "    " << passed << " of " << tests.size() << " tests passed" << std::endl;
    if (passed != tests.size()) {
        ret = 1;
        std::cout << std::endl << "   Please notify developer" << std::endl;
        std::cout << "  " << passed_h << " passed hashing check" << std::endl
                  << "  " << passed_h << " passed comparison check" << std::endl;
    }
    std::cout << "*******************************" << std::endl;

	return ret;
}

int read_input(int argc, char** argv) {
    sha1::sha1_t sha1;
    unsigned char* digest;
    const unsigned int buffer_size = 8192;

    assert( argv[1] );

    if (argv[1][0] == '-') {

    }

    /* open the file */
    int fd = open( argv[1], O_RDONLY | O_BINARY, 0 );
    /* handle open failure */
    if( fd == -1 ) {
        fprintf( stderr, "cannot open file %s\n", argv[1] );
        return 1;
        }

    /* prepare to calculate the SHA-1 hash */
    char* buffer = (char*)malloc( buffer_size );
    assert( buffer );

    /* loop through the file */
    int ret;
    while( true ) {
        /* read a chunk of data */
        ret = read( fd, buffer, buffer_size );
        /* check for error and end of file */
        if( ret < 1 ) break;
        /* run this data through the hash function */
        sha1.process(buffer, ret);
        }

    /* close the file */
    close( fd );

    /* there was an error reading the file */
    if( ret == -1 ) {
        fprintf( stderr, "error reading %s.\n", argv[1] );
        return 1;
        }

    /* get the digest */
    sha1.finish(digest);
    assert( digest );
    /* print it out */
    printf( "%s:", argv[1] );
    printf( "\n" );
    fflush( stdout );
    free( digest );
    return 0;
}

int main(int argc, char* argv[])
{
	if( argc == 2 ) {
        return read_input(argc, argv);
	} else {
        return run_tests();
	}
}

