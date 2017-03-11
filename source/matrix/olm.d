module matrix.olm;

struct OlmAccount;
struct OlmSession;
struct OlmUtility;

import std.file : read;
import std.experimental.allocator : processAllocator;
import std.exception : assumeUnique;

immutable(char)[] cstr2dstr(inout(char)* cstr)
{
	import core.stdc.string: strlen;
	return cstr ? cstr[0 .. strlen(cstr)].idup : cstr[0 .. 0].idup;
}

class Account {
	OlmAccount* account;
	private this() {
		const len = olm_account_size();
		this.account = cast (OlmAccount*) processAllocator.allocate(len).ptr;
	}
	/// Create a fresh account, generate keys, etc
	static public Account create() {
		auto a = new Account();
		const rnd_len = olm_create_account_random_length(a.account);
		auto rnd_mem = read("/dev/urandom", rnd_len);
		olm_create_account(a.account, rnd_mem.ptr, rnd_len);
		return a;
	}
	/// serialize account data, locked by key
	public string pickle(string key) {
		char[] ret;
		ret.length = olm_pickle_account_length(this.account);
		const actual_len = olm_pickle_account(this.account,
			key.ptr, key.length, ret.ptr, ret.length);
		if (actual_len == olm_error()) {
			auto msg = olm_account_last_error(this.account);
			throw new Exception(cstr2dstr(msg));
		}
		return assumeUnique(ret);
	}
	/// deserialize account data, unlocked by key
	static public Account unpickle(string key, string pickle) {
		auto a = new Account();
		char[] p = pickle.dup; // p is destroyed!
		const r = olm_unpickle_account(a.account,
			key.ptr, key.length, p.ptr, p.length);
		if (r == olm_error()) {
			auto msg = olm_account_last_error(a.account);
			throw new Exception(cstr2dstr(msg));
		}
		return a;
	}
	/// returns a JSON string of identity keys
	public string identity_keys() {
		char[] ret;
		ret.length = olm_account_identity_keys_length(this.account);
		const r = olm_account_identity_keys(this.account,
			 ret.ptr, ret.length);
		if (r == olm_error()) {
			auto msg = olm_account_last_error(this.account);
			throw new Exception(cstr2dstr(msg));
		}
		return assumeUnique(ret);
	}
	/// sign a message
	public string sign(string msg) {
		char[] ret;
		ret.length = olm_account_signature_length(this.account);
		const r = olm_account_sign(this.account,
			msg.ptr, msg.length, ret.ptr, ret.length);
		if (r == olm_error()) {
			auto errmsg = olm_account_last_error(this.account);
			throw new Exception(cstr2dstr(errmsg));
		}
		return assumeUnique(ret);
	}
	/// returns a JSON string of one time keys (pre keys)
	public string one_time_keys() {
		char[] ret;
		ret.length = olm_account_one_time_keys_length(this.account);
		const r = olm_account_one_time_keys(this.account,
			ret.ptr, ret.length);
		if (r == olm_error()) {
			auto errmsg = olm_account_last_error(this.account);
			throw new Exception(cstr2dstr(errmsg));
		}
		return assumeUnique(ret);
	}
	public void mark_keys_as_published() {
		olm_account_mark_keys_as_published(this.account);
	}
	public size_t max_number_of_one_time_keys() {
		return olm_account_max_number_of_one_time_keys(this.account);
	}
	public void generate_one_time_keys(size_t count) {
		const rnd_len = olm_account_generate_one_time_keys_random_length(this.account, count);
		auto rnd_mem = read("/dev/urandom", rnd_len);
		const r = olm_account_generate_one_time_keys(this.account,
			count, rnd_mem.ptr, rnd_mem.length);
	}
}

extern (C):
// copy&pasted from olm.h

/** Get the version number of the library.
 * Arguments will be updated if non-null.
 */
void olm_get_library_version(ubyte *major, ubyte *minor, ubyte *patch);

/** The size of an account object in bytes */
size_t olm_account_size();

/** The size of a session object in bytes */
size_t olm_session_size();

/** The size of a utility object in bytes */
size_t olm_utility_size();

/** Initialise an account object using the supplied memory
 *  The supplied memory must be at least olm_account_size() bytes */
OlmAccount * olm_account(
    void * memory
);

/** Initialise a session object using the supplied memory
 *  The supplied memory must be at least olm_session_size() bytes */
OlmSession * olm_session(
    void * memory
);

/** Initialise a utility object using the supplied memory
 *  The supplied memory must be at least olm_utility_size() bytes */
OlmUtility * olm_utility(
    void * memory
);

/** The value that olm will return from a function if there was an error */
size_t olm_error();

/** A null terminated string describing the most recent error to happen to an
 * account */
const(char*) olm_account_last_error(
    OlmAccount * account
);

/** A null terminated string describing the most recent error to happen to a
 * session */
const(char*) olm_session_last_error(
    OlmSession * session
);

/** A null terminated string describing the most recent error to happen to a
 * utility */
const(char*) olm_utility_last_error(
    OlmUtility * utility
);

/** Clears the memory used to back this account */
size_t olm_clear_account(
    OlmAccount * account
);

/** Clears the memory used to back this session */
size_t olm_clear_session(
    OlmSession * session
);

/** Clears the memory used to back this utility */
size_t olm_clear_utility(
    OlmUtility * utility
);

/** Returns the number of bytes needed to store an account */
size_t olm_pickle_account_length(
    OlmAccount * account
);

/** Returns the number of bytes needed to store a session */
size_t olm_pickle_session_length(
    OlmSession * session
);

/** Stores an account as a base64 string. Encrypts the account using the
 * supplied key. Returns the length of the pickled account on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_account_length() then
 * olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_pickle_account(
    OlmAccount * account,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** Stores a session as a base64 string. Encrypts the session using the
 * supplied key. Returns the length of the pickled session on success.
 * Returns olm_error() on failure. If the pickle output buffer
 * is smaller than olm_pickle_session_length() then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_pickle_session(
    OlmSession * session,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** Loads an account from a pickled base64 string. Decrypts the account using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_account_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_account_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
size_t olm_unpickle_account(
    OlmAccount * account,
    const(void)* key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** Loads a session from a pickled base64 string. Decrypts the session using
 * the supplied key. Returns olm_error() on failure. If the key doesn't
 * match the one used to encrypt the account then olm_session_last_error()
 * will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
 * olm_session_last_error() will be "INVALID_BASE64". The input pickled
 * buffer is destroyed */
size_t olm_unpickle_session(
    OlmSession * session,
    const void * key, size_t key_length,
    void * pickled, size_t pickled_length
);

/** The number of random bytes needed to create an account.*/
size_t olm_create_account_random_length(
    OlmAccount * account
);

/** Creates a new account. Returns olm_error() on failure. If weren't
 * enough random bytes then olm_account_last_error() will be
 * "NOT_ENOUGH_RANDOM" */
size_t olm_create_account(
    OlmAccount * account,
    void * random, size_t random_length
);

/** The size of the output buffer needed to hold the identity keys */
size_t olm_account_identity_keys_length(
    OlmAccount * account
);

/** Writes the public parts of the identity keys for the account into the
 * identity_keys output buffer. Returns olm_error() on failure. If the
 * identity_keys buffer was too small then olm_account_last_error() will be
 * "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_account_identity_keys(
    OlmAccount * account,
    void * identity_keys, size_t identity_key_length
);


/** The length of an ed25519 signature encoded as base64. */
size_t olm_account_signature_length(
    OlmAccount * account
);

/** Signs a message with the ed25519 key for this account. Returns olm_error()
 * on failure. If the signature buffer was too small then
 * olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL" */
size_t olm_account_sign(
    OlmAccount * account,
    const void * message, size_t message_length,
    void * signature, size_t signature_length
);

/** The size of the output buffer needed to hold the one time keys */
size_t olm_account_one_time_keys_length(
    OlmAccount * account
);

/** Writes the public parts of the unpublished one time keys for the account
 * into the one_time_keys output buffer.
 * <p>
 * The returned data is a JSON-formatted object with the single property
 * <tt>curve25519</tt>, which is itself an object mapping key id to
 * base64-encoded Curve25519 key. For example:
 * <pre>
 * {
 *     curve25519: {
 *         "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
 *         "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
 *     }
 * }
 * </pre>
 * Returns olm_error() on failure.
 * <p>
 * If the one_time_keys buffer was too small then olm_account_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_account_one_time_keys(
    OlmAccount * account,
    void * one_time_keys, size_t one_time_keys_length
);

/** Marks the current set of one time keys as being published. */
size_t olm_account_mark_keys_as_published(
    OlmAccount * account
);

/** The largest number of one time keys this account can store. */
size_t olm_account_max_number_of_one_time_keys(
    OlmAccount * account
);

/** The number of random bytes needed to generate a given number of new one
 * time keys. */
size_t olm_account_generate_one_time_keys_random_length(
    OlmAccount * account,
    size_t number_of_keys
);

/** Generates a number of new one time keys. If the total number of keys stored
 * by this account exceeds max_number_of_one_time_keys() then the old keys are
 * discarded. Returns olm_error() on error. If the number of random bytes is
 * too small then olm_account_last_error() will be "NOT_ENOUGH_RANDOM". */
size_t olm_account_generate_one_time_keys(
    OlmAccount * account,
    size_t number_of_keys,
    void * random, size_t random_length
);

/** The number of random bytes needed to create an outbound session */
size_t olm_create_outbound_session_random_length(
    OlmSession * session
);

/** Creates a new out-bound session for sending messages to a given identity_key
 * and one_time_key. Returns olm_error() on failure. If the keys couldn't be
 * decoded as base64 then olm_session_last_error() will be "INVALID_BASE64"
 * If there weren't enough random bytes then olm_session_last_error() will
 * be "NOT_ENOUGH_RANDOM". */
size_t olm_create_outbound_session(
    OlmSession * session,
    OlmAccount * account,
    const void * their_identity_key, size_t their_identity_key_length,
    const void * their_one_time_key, size_t their_one_time_key_length,
    void * random, size_t random_length
);

/** Create a new in-bound session for sending/receiving messages from an
 * incoming PRE_KEY message. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
 * key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID". */
size_t olm_create_inbound_session(
    OlmSession * session,
    OlmAccount * account,
    void * one_time_key_message, size_t message_length
);

/** Create a new in-bound session for sending/receiving messages from an
 * incoming PRE_KEY message. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
 * key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID". */
size_t olm_create_inbound_session_from(
    OlmSession * session,
    OlmAccount * account,
    const void * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
);

/** The length of the buffer needed to return the id for this session. */
size_t olm_session_id_length(
    OlmSession * session
);

/** An identifier for this session. Will be the same for both ends of the
 * conversation. If the id buffer is too small then olm_session_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_session_id(
    OlmSession * session,
    void * id, size_t id_length
);

int olm_session_has_received_message(
    OlmSession *session
);

/** Checks if the PRE_KEY message is for this in-bound session. This can happen
 * if multiple messages are sent to this account before this account sends a
 * message in reply. Returns 1 if the session matches. Returns 0 if the session
 * does not match. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
size_t olm_matches_inbound_session(
    OlmSession * session,
    void * one_time_key_message, size_t message_length
);

/** Checks if the PRE_KEY message is for this in-bound session. This can happen
 * if multiple messages are sent to this account before this account sends a
 * message in reply. Returns 1 if the session matches. Returns 0 if the session
 * does not match. Returns olm_error() on failure. If the base64
 * couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
 * If the message was for an unsupported protocol version then
 * olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
 * couldn't be decoded then then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
size_t olm_matches_inbound_session_from(
    OlmSession * session,
    const void * their_identity_key, size_t their_identity_key_length,
    void * one_time_key_message, size_t message_length
);

/** Removes the one time keys that the session used from the account. Returns
 * olm_error() on failure. If the account doesn't have any matching one time
 * keys then olm_account_last_error() will be "BAD_MESSAGE_KEY_ID". */
size_t olm_remove_one_time_keys(
    OlmAccount * account,
    OlmSession * session
);

/** The type of the next message that olm_encrypt() will return. Returns
 * OLM_MESSAGE_TYPE_PRE_KEY if the message will be a PRE_KEY message.
 * Returns OLM_MESSAGE_TYPE_MESSAGE if the message will be a normal message.
 * Returns olm_error on failure. */
size_t olm_encrypt_message_type(
    OlmSession * session
);

/** The number of random bytes needed to encrypt the next message. */
size_t olm_encrypt_random_length(
    OlmSession * session
);

/** The size of the next message in bytes for the given number of plain-text
 * bytes. */
size_t olm_encrypt_message_length(
    OlmSession * session,
    size_t plaintext_length
);

/** Encrypts a message using the session. Returns the length of the message in
 * bytes on success. Writes the message as base64 into the message buffer.
 * Returns olm_error() on failure. If the message buffer is too small then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". If there
 * weren't enough random bytes then olm_session_last_error() will be
 * "NOT_ENOUGH_RANDOM". */
size_t olm_encrypt(
    OlmSession * session,
    const void * plaintext, size_t plaintext_length,
    void * random, size_t random_length,
    void * message, size_t message_length
);

/** The maximum number of bytes of plain-text a given message could decode to.
 * The actual size could be different due to padding. The input message buffer
 * is destroyed. Returns olm_error() on failure. If the message base64
 * couldn't be decoded then olm_session_last_error() will be
 * "INVALID_BASE64". If the message is for an unsupported version of the
 * protocol then olm_session_last_error() will be "BAD_MESSAGE_VERSION".
 * If the message couldn't be decoded then olm_session_last_error() will be
 * "BAD_MESSAGE_FORMAT". */
size_t olm_decrypt_max_plaintext_length(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length
);

/** Decrypts a message using the session. The input message buffer is destroyed.
 * Returns the length of the plain-text on success. Returns olm_error() on
 * failure. If the plain-text buffer is smaller than
 * olm_decrypt_max_plaintext_length() then olm_session_last_error()
 * will be "OUTPUT_BUFFER_TOO_SMALL". If the base64 couldn't be decoded then
 * olm_session_last_error() will be "INVALID_BASE64". If the message is for
 * an unsupported version of the protocol then olm_session_last_error() will
 *  be "BAD_MESSAGE_VERSION". If the message couldn't be decoded then
 *  olm_session_last_error() will be BAD_MESSAGE_FORMAT".
 *  If the MAC on the message was invalid then olm_session_last_error() will
 *  be "BAD_MESSAGE_MAC". */
size_t olm_decrypt(
    OlmSession * session,
    size_t message_type,
    void * message, size_t message_length,
    void * plaintext, size_t max_plaintext_length
);

/** The length of the buffer needed to hold the SHA-256 hash. */
size_t olm_sha256_length(
   OlmUtility * utility
);

/** Calculates the SHA-256 hash of the input and encodes it as base64. If the
 * output buffer is smaller than olm_sha256_length() then
 * olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". */
size_t olm_sha256(
    OlmUtility * utility,
    const void * input, size_t input_length,
    void * output, size_t output_length
);

/** Verify an ed25519 signature. If the key was too small then
 * olm_session_last_error will be "INVALID_BASE64". If the signature was invalid
 * then olm_session_last_error() will be "BAD_MESSAGE_MAC". */
size_t olm_ed25519_verify(
    OlmUtility * utility,
    const void * key, size_t key_length,
    const void * message, size_t message_length,
    void * signature, size_t signature_length
);
