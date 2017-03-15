module matrix.outbound_group;

import std.file : read;
import std.experimental.allocator : processAllocator;
import std.exception : assumeUnique;

import matrix.olm : cstr2dstr, olm_error, read_random;

import std.stdio; // TODO debug only!

class OutboundGroupSession {
    OlmOutboundGroupSession *session;
    private this() {
        const len = olm_outbound_group_session_size();
        auto mem = processAllocator.allocate(len);
        this.session = olm_outbound_group_session(mem.ptr);

        auto rnd_len = olm_init_outbound_group_session_random_length(session);
        auto rnd_mem = read_random(rnd_len);
        olm_init_outbound_group_session(session, rnd_mem.ptr, rnd_mem.length);
    }
    /// serialize session data, locked by key
    public string pickle(string key) {
        char[] ret;
        ret.length = olm_pickle_outbound_group_session_length(this.session);
        const r = olm_pickle_outbound_group_session(this.session,
                key.ptr, key.length, ret.ptr, ret.length);
        error_check(r);
        return assumeUnique(ret);
    }
    /// deserialize session data, unlocked by key
    static public OutboundGroupSession unpickle(string key, string pickle) {
        auto a = new OutboundGroupSession();
        char[] p = pickle.dup; // p is destroyed!
        const r = olm_unpickle_outbound_group_session(a.session,
                key.ptr, key.length, p.ptr, p.length);
        a.error_check(r);
        return a;
    }
    public string encrypt(string plain) {
        auto len = olm_group_encrypt_message_length(session, plain.length);
        error_check(len);
        char[] ret;
        ret.length = len;
        len = olm_group_encrypt(session, plain.ptr, plain.length, ret.ptr, len);
        error_check(len);
        return assumeUnique(ret[0..len]);
    }
    public string session_id() {
        auto len = olm_outbound_group_session_id_length(session);
        char[] ret;
        auto r = olm_outbound_group_session_id(session, ret.ptr, len);
        error_check(r);
        return assumeUnique(ret);
    }
    public @property uint message_index() {
        return olm_outbound_group_session_message_index(session);
    }
    public auto session_key() {
        char[] ret;
        ret.length = olm_outbound_group_session_key_length(session);
        auto r = olm_outbound_group_session_key(session, ret.ptr, ret.length);
        error_check(r);
        return assumeUnique(ret);

    }
    private void error_check(size_t x) {
        if (x == olm_error()) {
            auto errmsg = olm_outbound_group_session_last_error(this.session);
            throw new Exception(cstr2dstr(errmsg));
        }
    }
}

unittest {
    auto igs = new OutboundGroupSession();
    auto p = igs.pickle("foo");
    auto dp = OutboundGroupSession.unpickle("foo", p);
}


extern (C):
// copy&pasted from outbound_group_session.h

struct OlmOutboundGroupSession;

/** get the size of an outbound group session, in bytes. */
size_t olm_outbound_group_session_size();

/**
 * Initialise an outbound group session object using the supplied memory
 * The supplied memory should be at least olm_outbound_group_session_size()
 * bytes.
 */
OlmOutboundGroupSession * olm_outbound_group_session(
    void *memory
);

/**
 * A null terminated string describing the most recent error to happen to a
 * group session */
const(char)* olm_outbound_group_session_last_error(
    const OlmOutboundGroupSession *session
);

/** Clears the memory used to back this group session */
size_t olm_clear_outbound_group_session(
    OlmOutboundGroupSession *session
);

/** Returns the number of bytes needed to store an outbound group session */
size_t olm_pickle_outbound_group_session_length(
    const OlmOutboundGroupSession *session
);

/**
 * Stores a group session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the session on success.
 *
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_outbound_group_session_length() then
 * olm_outbound_group_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
 */
size_t olm_pickle_outbound_group_session(
    OlmOutboundGroupSession *session,
    const(void)* key, size_t key_length,
    void * pickled, size_t pickled_length
);

/**
 * Loads a group session from a pickled base64 string. Decrypts the session
 * using the supplied key.
 *
 * Returns olm_error() on failure. If the key doesn't match the one used to
 * encrypt the account then olm_outbound_group_session_last_error() will be
 * "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_outbound_group_session_last_error() will be "INVALID_BASE64". The input
 * pickled buffer is destroyed
 */
size_t olm_unpickle_outbound_group_session(
    OlmOutboundGroupSession *session,
    const(void)* key, size_t key_length,
    void * pickled, size_t pickled_length
);


/** The number of random bytes needed to create an outbound group session */
size_t olm_init_outbound_group_session_random_length(
    const OlmOutboundGroupSession *session
);

/**
 * Start a new outbound group session. Returns olm_error() on failure. On
 * failure last_error will be set with an error code. The last_error will be
 * NOT_ENOUGH_RANDOM if the number of random bytes was too small.
 */
size_t olm_init_outbound_group_session(
    OlmOutboundGroupSession *session,
    char* random, size_t random_length
);

/**
 * The number of bytes that will be created by encrypting a message
 */
size_t olm_group_encrypt_message_length(
    OlmOutboundGroupSession *session,
    size_t plaintext_length
);

/**
 * Encrypt some plain-text. Returns the length of the encrypted message or
 * olm_error() on failure. On failure last_error will be set with an
 * error code. The last_error will be OUTPUT_BUFFER_TOO_SMALL if the output
 * buffer is too small.
 */
size_t olm_group_encrypt(
    OlmOutboundGroupSession *session,
    const(char)* plaintext, size_t plaintext_length,
    char* message, size_t message_length
);


/**
 * Get the number of bytes returned by olm_outbound_group_session_id()
 */
size_t olm_outbound_group_session_id_length(
    const OlmOutboundGroupSession *session
);

/**
 * Get a base64-encoded identifier for this session.
 *
 * Returns the length of the session id on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be OUTPUT_BUFFER_TOO_SMALL if the id buffer was too
 * small.
 */
size_t olm_outbound_group_session_id(
    OlmOutboundGroupSession *session,
    char* id, size_t id_length
);

/**
 * Get the current message index for this session.
 *
 * Each message is sent with an increasing index; this returns the index for
 * the next message.
 */
uint olm_outbound_group_session_message_index(
    OlmOutboundGroupSession *session
);

/**
 * Get the number of bytes returned by olm_outbound_group_session_key()
 */
size_t olm_outbound_group_session_key_length(
    const OlmOutboundGroupSession *session
);

/**
 * Get the base64-encoded current ratchet key for this session.
 *
 * Each message is sent with a different ratchet key. This function returns the
 * ratchet key that will be used for the next message.
 *
 * Returns the length of the ratchet key on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be OUTPUT_BUFFER_TOO_SMALL if the buffer was too small.
 */
size_t olm_outbound_group_session_key(
    OlmOutboundGroupSession *session,
    char* key, size_t key_length
);
