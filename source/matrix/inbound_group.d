module matrix.inbound_group;

import std.file : read;
import std.experimental.allocator : processAllocator;
import std.exception : assumeUnique;

import matrix.olm : cstr2dstr, olm_error;

import std.stdio; // TODO debug only!

public class InboundGroupSession {
    OlmInboundGroupSession *session;
    private this() {
        const len = olm_inbound_group_session_size();
        auto mem = processAllocator.allocate(len);
        this.session = olm_inbound_group_session(mem.ptr);
    }
    /// serialize session data, locked by key
    public string pickle(string key) {
        char[] ret;
        ret.length = olm_pickle_inbound_group_session_length(this.session);
        const r = olm_pickle_inbound_group_session(this.session,
                key.ptr, key.length, ret.ptr, ret.length);
        error_check(r);
        return assumeUnique(ret);
    }
    /// deserialize session data, unlocked by key
    static public InboundGroupSession unpickle(string key, string pickle) {
        auto a = new InboundGroupSession();
        char[] p = pickle.dup; // p is destroyed!
        const r = olm_unpickle_inbound_group_session(a.session,
                key.ptr, key.length, p.ptr, p.length);
        a.error_check(r);
        return a;
    }
    static public InboundGroupSession init(string session_key) {
        auto s = new InboundGroupSession();
        olm_init_inbound_group_session(s.session, session_key.ptr, session_key.length);
        return s;
    }
    static public InboundGroupSession import_session(string session_key) {
        auto s = new InboundGroupSession();
        olm_import_inbound_group_session(s.session, session_key.ptr, session_key.length);
        return s;
    }
    public string decrypt(string msg, uint* msg_index) {
        char[] dummy = msg.dup; // dummy is destroyed!
        auto len = olm_group_decrypt_max_plaintext_length(session,
            dummy.ptr, dummy.length);
        error_check(len);
        char[] ret;
        ret.length = len;
        dummy = msg.dup; // dummy is destroyed!
        len = olm_group_decrypt(session, dummy.ptr, dummy.length,
            ret.ptr, len, msg_index);
        error_check(len);
        return assumeUnique(ret[0..len]);
    }
    public string session_id() {
        char[] ret;
        ret.length = olm_inbound_group_session_id_length(session);
        auto r = olm_inbound_group_session_id(session, ret.ptr, ret.length);
        error_check(r);
        return assumeUnique(ret);
    }
    public @property uint first_known_index() const {
        return olm_inbound_group_session_first_known_index(session);
    }
    public auto export_session(uint message_index) {
        auto len = olm_export_inbound_group_session_length(session);
        char[] ret;
        ret.length = len;
        auto r = olm_export_inbound_group_session(session,
            ret.ptr, len, message_index);
        error_check(r);
        return assumeUnique(ret);

    }
    private void error_check(size_t x) {
        if (x == olm_error()) {
            auto errmsg = olm_inbound_group_session_last_error(this.session);
            throw new Exception(cstr2dstr(errmsg));
        }
    }
}

unittest {
    auto igs = new InboundGroupSession();
    auto p = igs.pickle("foo");
    auto dp = InboundGroupSession.unpickle("foo", p);
}

unittest {
    import matrix.outbound_group;
    auto ogs = new OutboundGroupSession();
    auto session_key = ogs.session_key;
    auto plain = "Hello World!";
    auto cypher = ogs.encrypt(plain);
    /* transfer: session_key, cypher, msg_index */
    uint msg_index;
    auto igs = InboundGroupSession.init(session_key);
    auto dec = igs.decrypt(cypher, &msg_index);
}

extern (C):
// copy&pasted from inbound_group_session.h
struct OlmInboundGroupSession;

/** get the size of an inbound group session, in bytes. */
size_t olm_inbound_group_session_size();

/**
 * Initialise an inbound group session object using the supplied memory
 * The supplied memory should be at least olm_inbound_group_session_size()
 * bytes.
 */
OlmInboundGroupSession * olm_inbound_group_session(
    void *memory
);

/**
 * A null terminated string describing the most recent error to happen to a
 * group session */
const(char)* olm_inbound_group_session_last_error(
    const OlmInboundGroupSession *session
);

/** Clears the memory used to back this group session */
size_t olm_clear_inbound_group_session(
    OlmInboundGroupSession *session
);

/** Returns the number of bytes needed to store an inbound group session */
size_t olm_pickle_inbound_group_session_length(
    const OlmInboundGroupSession *session
);

/**
 * Stores a group session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the session on success.
 *
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_inbound_group_session_length() then
 * olm_inbound_group_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
 */
size_t olm_pickle_inbound_group_session(
    OlmInboundGroupSession *session,
    const(void)* key, size_t key_length,
    void * pickled, size_t pickled_length
);

/**
 * Loads a group session from a pickled base64 string. Decrypts the session
 * using the supplied key.
 *
 * Returns olm_error() on failure. If the key doesn't match the one used to
 * encrypt the account then olm_inbound_group_session_last_error() will be
 * "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_inbound_group_session_last_error() will be "INVALID_BASE64". The input
 * pickled buffer is destroyed
 */
size_t olm_unpickle_inbound_group_session(
    OlmInboundGroupSession *session,
    const(void)* key, size_t key_length,
    void * pickled, size_t pickled_length
);


/**
 * Start a new inbound group session, from a key exported from
 * olm_outbound_group_session_key
 *
 * Returns olm_error() on failure. On failure last_error will be set with an
 * error code. The last_error will be:
 *
 *  * OLM_INVALID_BASE64  if the session_key is not valid base64
 *  * OLM_BAD_SESSION_KEY if the session_key is invalid
 */
size_t olm_init_inbound_group_session(
    OlmInboundGroupSession *session,
    /* base64-encoded keys */
    const(char)* session_key, size_t session_key_length
);

/**
 * Import an inbound group session, from a previous export.
 *
 * Returns olm_error() on failure. On failure last_error will be set with an
 * error code. The last_error will be:
 *
 *  * OLM_INVALID_BASE64  if the session_key is not valid base64
 *  * OLM_BAD_SESSION_KEY if the session_key is invalid
 */
size_t olm_import_inbound_group_session(
    OlmInboundGroupSession *session,
    /* base64-encoded keys; note that it will be overwritten with the base64-decoded
       data. */
    const(char)* session_key, size_t session_key_length
);


/**
 * Get an upper bound on the number of bytes of plain-text the decrypt method
 * will write for a given input message length. The actual size could be
 * different due to padding.
 *
 * The input message buffer is destroyed.
 *
 * Returns olm_error() on failure.
 */
size_t olm_group_decrypt_max_plaintext_length(
    OlmInboundGroupSession *session,
    char* message, size_t message_length
);

/**
 * Decrypt a message.
 *
 * The input message buffer is destroyed.
 *
 * Returns the length of the decrypted plain-text, or olm_error() on failure.
 *
 * On failure last_error will be set with an error code. The last_error will
 * be:
 *   * OLM_OUTPUT_BUFFER_TOO_SMALL if the plain-text buffer is too small
 *   * OLM_INVALID_BASE64 if the message is not valid base-64
 *   * OLM_BAD_MESSAGE_VERSION if the message was encrypted with an unsupported
 *     version of the protocol
 *   * OLM_BAD_MESSAGE_FORMAT if the message headers could not be decoded
 *   * OLM_BAD_MESSAGE_MAC    if the message could not be verified
 *   * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key corresponding to the
 *     message's index (ie, it was sent before the session key was shared with
 *     us)
 */
size_t olm_group_decrypt(
    OlmInboundGroupSession *session,

    /* input; note that it will be overwritten with the base64-decoded
       message. */
    char* message, size_t message_length,

    /* output */
    char* plaintext, size_t max_plaintext_length,
    uint * message_index
);


/**
 * Get the number of bytes returned by olm_inbound_group_session_id()
 */
size_t olm_inbound_group_session_id_length(
    const OlmInboundGroupSession *session
);

/**
 * Get a base64-encoded identifier for this session.
 *
 * Returns the length of the session id on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be OUTPUT_BUFFER_TOO_SMALL if the id buffer was too
 * small.
 */
size_t olm_inbound_group_session_id(
    OlmInboundGroupSession *session,
    char* id, size_t id_length
);

/**
 * Get the first message index we know how to decrypt.
 */
uint olm_inbound_group_session_first_known_index(
    const OlmInboundGroupSession *session
);


/**
 * Check if the session has been verified as a valid session.
 *
 * (A session is verified either because the original session share was signed,
 * or because we have subsequently successfully decrypted a message.)
 *
 * This is mainly intended for the unit tests, currently.
 */
int olm_inbound_group_session_is_verified(
    const OlmInboundGroupSession *session
);

/**
 * Get the number of bytes returned by olm_export_inbound_group_session()
 */
size_t olm_export_inbound_group_session_length(
    const OlmInboundGroupSession *session
);

/**
 * Export the base64-encoded ratchet key for this session, at the given index,
 * in a format which can be used by olm_import_inbound_group_session
 *
 * Returns the length of the ratchet key on success or olm_error() on
 * failure. On failure last_error will be set with an error code. The
 * last_error will be:
 *   * OUTPUT_BUFFER_TOO_SMALL if the buffer was too small
 *   * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key corresponding to the
 *     given index (ie, it was sent before the session key was shared with
 *     us)
 */
size_t olm_export_inbound_group_session(
    OlmInboundGroupSession *session,
    char* key, size_t key_length, uint message_index
);

