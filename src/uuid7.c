#include <assert.h>
#include <time.h>

#include "sqlite3ext.h"
SQLITE_EXTENSION_INIT1

#define MAX_ROLLBACK 60 * 60 * 48

/*
 * https://www.ietf.org/archive/id/draft-ietf-uuidrev-rfc4122bis-11.html#name-uuid-version-7
 * 0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           unix_ts_ms                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          unix_ts_ms           |  ver  |     unix_ts_fr_ms     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |var|cro|                   counter                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           rand                                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 0                 1                 2                 3                 4
 *  0 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8 0 1 2 3 4 5 6 7 8
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              unix_ts_ms                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            unix_ts_ms             |  ver  |       unix_ts_fr_ms       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |var|cro|                   counter                    |      rand      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                 rand                                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * unix_ts_ms:
 *   48 bit big-endian unsigned number of Unix epoch timestamp in milliseconds
 *   Occupies bits 0 through 47 (octets 0-5)
 * ver:
 *   4 bit version field set to 0b0111 (7)
 *   Occupies bits 48 through 51 of octet 6
 * unix_ts_fr_ms:
 *   12 bits of fractional milliseconds to guarantee additional monotonicity
 *   Occupies bits 52 through 63 (octets 6-7)
 * var:
 *   2 bit variant field set to 0b10 (2)
 *   Occupies bits 64 and 65 of octet 8
 * cro:
 *   2 bits used for counter rollover
 *   Occupies bits 66 and 67 of octet 8
 * counter:
 *   28 bit counter to guarantee additional monotonicity
 *   Occupies bits 68 through 96 (octets 8-10)
 * rand:
 *   Final 60 bits of pseudo-random data to provide uniqueness
 *   Occupies bits 97 through 127 (octets 11-15)
 */

// copied from main src/uuid/extension.c
/*
 * Convert a 16-byte BLOB into a well-formed RFC-4122 UUID.  The output
 * buffer zStr should be at least 37 bytes in length.   The output will
 * be zero-terminated.
 */
static void sqlite3_uuid_blob_to_str(const unsigned char* aBlob, /* Input blob */
                                     unsigned char* zStr         /* Write the answer here */
) {
    static const char zDigits[] = "0123456789abcdef";
    int i, k;
    unsigned char x;
    k = 0;
    for (i = 0, k = 0x550; i < 16; i++, k = k >> 1) {
        if (k & 1) {
            zStr[0] = '-';
            zStr++;
        }
        x = aBlob[i];
        zStr[0] = zDigits[x >> 4];
        zStr[1] = zDigits[x & 0xf];
        zStr += 2;
    }
    *zStr = 0;
}

// uuid7_generate generates a version 7 UUID as a string
static void uuid7_generate(sqlite3_context* context, int argc, sqlite3_value** argv) {
    static time_t last_sec = 0;
    static time_t last_nsec = 0;
    static unsigned long current_counter = 0;

    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        sqlite3_result_error(context, "Error in uuid7_generate: failed to acquire timestamp", -1);
        return;
    }
    if (ts.tv_sec > last_sec || (ts.tv_sec == last_sec && ts.tv_nsec > last_nsec)) {
        last_sec = ts.tv_sec;
        last_nsec = ts.tv_nsec;
        sqlite3_randomness(sizeof(current_counter), &current_counter);
        // reserve bits for cro
        current_counter &= 0xFFFFF;
    } else if (ts.tv_sec + MAX_ROLLBACK > last_sec) {
        current_counter++;
    } else {
        sqlite3_result_error(
            context, "Error in uuid7_generate: time went backward beyond maximum allowance", -1);
        return;
    }

    sqlite_uint64 unix_ts_ms_tmp = ts.tv_sec * 1000ull + ts.tv_nsec / 1000000;
    unsigned int unix_ts_fr_ms_tmp = (ts.tv_nsec % 1000000) / 1000000.0 * 4096;
    unsigned long counter_tmp = current_counter;
    unsigned long rand_tmp;
    sqlite3_randomness(sizeof(rand_tmp), &rand_tmp);

    unsigned char blob[16];
    // rand (60 bits)
    blob[15] = rand_tmp & 0xFF;
    rand_tmp >>= 8;
    blob[14] = rand_tmp & 0xFF;
    rand_tmp >>= 8;
    blob[13] = rand_tmp & 0xFF;
    rand_tmp >>= 8;
    blob[12] = rand_tmp & 0xFF;
    rand_tmp >>= 8;
    blob[11] = rand_tmp & 0xFF;
    rand_tmp >>= 8;
    // counter (16 bits)
    blob[10] = counter_tmp & 0xFF;
    counter_tmp >>= 8;
    blob[9] = counter_tmp & 0xFF;
    counter_tmp >>= 8;
    // var (2 bits) and cro with counter (6 bits)
    blob[8] = 0x80 | (counter_tmp & 0x3F);

    // unix_ts_fr_ms (8 bits)
    blob[7] = unix_ts_fr_ms_tmp & 0xFF;
    unix_ts_fr_ms_tmp >>= 8;
    // ver (4 bits) and unix_ts_fr_ms (4 bits)
    blob[6] = 0x70 | (unix_ts_fr_ms_tmp & 0xF);

    // unix_ts_ms (48 bits)
    blob[5] = unix_ts_ms_tmp & 0xFF;
    unix_ts_ms_tmp >>= 8;
    blob[4] = unix_ts_ms_tmp & 0xFF;
    unix_ts_ms_tmp >>= 8;
    blob[3] = unix_ts_ms_tmp & 0xFF;
    unix_ts_ms_tmp >>= 8;
    blob[2] = unix_ts_ms_tmp & 0xFF;
    unix_ts_ms_tmp >>= 8;
    blob[1] = unix_ts_ms_tmp & 0xFF;
    unix_ts_ms_tmp >>= 8;
    blob[0] = unix_ts_ms_tmp & 0xFF;
    unix_ts_ms_tmp >>= 8;

    unsigned char zStr[37];
    sqlite3_uuid_blob_to_str(blob, zStr);
    sqlite3_result_text(context, (char*)zStr, 36, SQLITE_TRANSIENT);
}

#ifdef _WIN32
__declspec(dllexport)
#endif
    int sqlite3_extension_init(sqlite3* db, char** pzErrMsg, const sqlite3_api_routines* pApi) {
    SQLITE_EXTENSION_INIT2(pApi);
    static const int flags = SQLITE_UTF8 | SQLITE_INNOCUOUS;
    sqlite3_create_function(db, "uuid7", 0, flags, 0, uuid7_generate, 0, 0);
    sqlite3_create_function(db, "uuid_generate_v7", 0, flags, 0, uuid7_generate, 0, 0);
    return SQLITE_OK;
}
