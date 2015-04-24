#ifndef SHA1_HEADER
#define SHA1_HEADER

const unsigned int SHA1_SIZE = (5 * sizeof(unsigned int));  /* 20 */
const unsigned int SHA1_STRING_SIZE = 2 * SHA1_SIZE + 1;    /* 41 */

namespace sha1 {

    /*
     * The SHA1 algorithm works on blocks of characters of 64 bytes.  This
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
             * Initialize structure containing state of SHA1 computation. This is
             * for progressive SHA1 calculations only.  If you have the complete
             * string available, call it as below. Process should be called for
             * each bunch of bytes and after the last process call, finish should
             * be called to get the signature.
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
             * input - A buffer of bytes whose SHA1 signature we are calculating.
             *
             * input_length - The length of the buffer.
             *
             * signature_ - A 20 byte buffer that will contain the SHA1 signature. This
             * function makes no attempts to ensure data will fit in the provided buffer;
             * this is the caller's responsibility.
             */
            sha1_t(const void* input, const unsigned int input_length, void* signature_);

            void process(const void* input, int input_length);

            void finish(void* signature_ = NULL);

            /*
             * get_sig
             *
             * DESCRIPTION:
             *
             * Retrieves the previously calculated signature from the SHA1 object. This
             * function makes no attempts to ensure data will fit in the provided buffer;
             * this is the caller's responsibility.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * signature_ - A 20 byte buffer that will contain the SHA1 signature.
             */
            void get_sig(void* signature_);

            /*
             * get_string
             *
             * DESCRIPTION:
             *
             * Retrieves the previously calculated signature from the SHA1 object in
             * printable format. This function makes no attempts to ensure data will fit in
             * the provided buffer; this is the caller's responsibility.
             *
             * RETURNS:
             *
             * None.
             *
             * ARGUMENTS:
             *
             * str_ - a string of characters which should be at least 41 bytes long
             * (2 characters per SHA1 byte and 1 for the \0).
             */
            void get_string(void* str_);

        private:
            // utility methods
            void initialise();

            void storeBigEndianUint32(unsigned char*, unsigned int);
            void process_block(const unsigned char*);

            // fields
            unsigned int H0;
            unsigned int H1;
            unsigned int H2;
            unsigned int H3;
            unsigned int H4;

            unsigned char stored[sha1::BLOCK_SIZE * 2];
            unsigned int stored_size;
            unsigned int message_length[2];

            unsigned char signature[SHA1_SIZE];           /* stored signature */
            char str[SHA1_STRING_SIZE];                       /* stored plain text hash */

            bool finished;
    };

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
     * signature - a 20 byte buffer that contains the SHA1 signature.
     *
     * str - a string of characters which should be at least 41 bytes long (2
     * characters per SHA1 byte and 1 for the \0).
     *
     * str_len - the length of the string.
     */
    extern void sig_to_string(const void* signature, char* str);

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
     * signature - A 40 byte buffer that will contain the SHA1 signature.
     *
     * str - A string of charactes which _must_ be at least 40 bytes long (2
     * characters per SHA1 byte).
     */
    extern void sig_from_string(void* signature, const char* str);

} // namescpace sha1

#endif
