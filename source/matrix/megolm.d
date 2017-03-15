module matrix.megolm;

extern (C):
// copy&pasted from megolm.h

/**
 * number of bytes in each part of the ratchet; this should be the same as
 * the length of the hash function used in the HMAC (32 bytes for us, as we
 * use HMAC-SHA-256)
 */
enum MEGOLM_RATCHET_PART_LENGTH = 32; /* SHA256_OUTPUT_LENGTH */

/**
 * number of parts in the ratchet; the advance() implementations rely on
 * this being 4.
 */
enum MEGOLM_RATCHET_PARTS = 4;

enum MEGOLM_RATCHET_LENGTH = (MEGOLM_RATCHET_PARTS * MEGOLM_RATCHET_PART_LENGTH);

struct Megolm {
    ubyte[MEGOLM_RATCHET_PARTS][MEGOLM_RATCHET_PART_LENGTH] data;
    uint counter;
};

struct _olm_cipher;


/**
 * The cipher used in megolm-backed conversations
 *
 * (AES256 + SHA256, with keys based on an HKDF with info of MEGOLM_KEYS)
 */
extern const _olm_cipher *megolm_cipher;

/**
 * initialize the megolm ratchet. random_data should be at least
 * MEGOLM_RATCHET_LENGTH bytes of randomness.
 */
void megolm_init(Megolm *megolm, const(ubyte)* random_data, uint counter);

/** Returns the number of bytes needed to store a megolm */
size_t megolm_pickle_length(const Megolm *megolm);

/**
 * Pickle the megolm. Returns a pointer to the next free space in the buffer.
 */
ubyte * megolm_pickle(const Megolm *megolm, ubyte *pos);

/**
 * Unpickle the megolm. Returns a pointer to the next item in the buffer.
 */
const(ubyte)* megolm_unpickle(Megolm *megolm,const(ubyte)* pos,
                                const(ubyte)* end);


/** advance the ratchet by one step */
void megolm_advance(Megolm *megolm);

/**
 * get the key data in the ratchet. The returned data is
 * MEGOLM_RATCHET_LENGTH bytes long.
 */
const(ubyte)* megolm_get_data(Megolm* megolm) {
    return cast(const ubyte *) (megolm.data);
}

/** advance the ratchet to a given count */
void megolm_advance_to(Megolm *megolm, uint advance_to);
