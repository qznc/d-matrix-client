/**
  Crypto for one-to-one aka Olm
  */
module matrix.session;

import matrix.olm;

import std.file : read;
import std.experimental.allocator : processAllocator;
import std.exception : assumeUnique;

import std.stdio; // TODO debug only!

immutable(char)[] cstr2dstr(inout(char)* cstr)
{
	import core.stdc.string: strlen;
	return cstr ? cstr[0 .. strlen(cstr)].idup : cstr[0 .. 0].idup;
}

class Account {
	OlmAccount* account;
	private this() {
		const len = olm_account_size();
		auto mem = processAllocator.allocate(len);
		this.account = olm_account(mem.ptr);
	}
	/// Create a fresh account, generate keys, etc
	static public Account create() {
		auto a = new Account();
		const rnd_len = olm_create_account_random_length(a.account);
		auto rnd_mem = read_random(rnd_len);
		olm_create_account(a.account, rnd_mem.ptr, rnd_len);
		return a;
	}
	/// serialize account data, locked by key
	public string pickle(string key) {
		char[] ret;
		ret.length = olm_pickle_account_length(this.account);
		const r = olm_pickle_account(this.account,
			key.ptr, key.length, ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret);
	}
	/// deserialize account data, unlocked by key
	static public Account unpickle(string key, string pickle) {
		auto a = new Account();
		char[] p = pickle.dup; // p is destroyed!
		const r = olm_unpickle_account(a.account,
			key.ptr, key.length, p.ptr, p.length);
		a.error_check(r);
		return a;
	}
	/// returns a JSON string of identity keys
	public @property string identity_keys() {
		char[] ret;
		ret.length = olm_account_identity_keys_length(this.account);
		const r = olm_account_identity_keys(this.account,
			 ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret);
	}
	/// sign a message
	public string sign(string msg) {
		char[] ret;
		ret.length = olm_account_signature_length(this.account);
		const r = olm_account_sign(this.account,
			msg.ptr, msg.length, ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret);
	}
	/// returns a JSON string of one time keys (pre keys)
	public @property string one_time_keys() {
		char[] ret;
		ret.length = olm_account_one_time_keys_length(this.account);
		const r = olm_account_one_time_keys(this.account,
			ret.ptr, ret.length);
		error_check(r);
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
		auto rnd_mem = read_random(rnd_len);
		const r = olm_account_generate_one_time_keys(this.account,
			count, rnd_mem.ptr, rnd_mem.length);
	}
	private void error_check(size_t x) {
		if (x == olm_error()) {
			auto errmsg = olm_account_last_error(this.account);
			throw new Exception(cstr2dstr(errmsg));
		}
	}
}

unittest {
	import std.json : parseJSON;
	auto a = Account.create();
	auto key = "foobar";
	auto p = a.pickle(key);
	auto a2 = Account.unpickle(key, p);
	auto id_keys = parseJSON(a.identity_keys());
	assert ("curve25519" in id_keys);
	assert ("ed25519" in id_keys);
	auto msg = "Hello World!";
	auto sig_msg = a.sign(msg);
	// TODO test signature

	auto max = a.max_number_of_one_time_keys();
	assert (max > 10);
	auto otks = a.one_time_keys();
	// none generated so far
	assert (otks == "{\"curve25519\":{}}");
	const key_count = 11;
	a.generate_one_time_keys(key_count);
	auto j_otks = parseJSON(a.one_time_keys());
	assert ("curve25519" in j_otks);
	assert(j_otks["curve25519"].object.length == key_count);
	auto j_otks2 = parseJSON(a.one_time_keys());
	assert (j_otks == j_otks2);
	a.mark_keys_as_published();
	auto j_otks3 = parseJSON(a.one_time_keys());
	assert ("curve25519" in j_otks3);
	assert(j_otks3["curve25519"].object.length == 0);
}

class Session {
	OlmSession* session;
	public this() {
		const len = olm_session_size();
		auto mem = processAllocator.allocate(len);
		this.session = olm_session(mem.ptr);
	}
	/// serialize session data, locked by key
	public string pickle(string key) {
		char[] ret;
		ret.length = olm_pickle_session_length(this.session);
		const r = olm_pickle_session(this.session,
			key.ptr, key.length, ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret);
	}
	/// deserialize session data, unlocked by key
	static public Session unpickle(string key, string pickle) {
		auto a = new Session();
		char[] p = pickle.dup; // p is destroyed!
		const r = olm_unpickle_session(a.session,
			key.ptr, key.length, p.ptr, p.length);
		a.error_check(r);
		return a;
	}
    static public Session create_outbound(Account a, string identity_key, string one_time_key) {
		auto s = new Session();
		const rnd_len = olm_create_outbound_session_random_length(s.session);
		auto rnd_mem = read_random(rnd_len);
		const r = olm_create_outbound_session(s.session,
			a.account, identity_key.ptr, identity_key.length,
			one_time_key.ptr, one_time_key.length,
			rnd_mem.ptr, rnd_mem.length);
		s.error_check(r);
		return s;
	}
	static public Session create_inbound(Account a, string one_time_key_msg) {
		auto s = new Session();
		char[] msg = one_time_key_msg.dup; // msg is destroyed!
		const r = olm_create_inbound_session(s.session, a.account,
			msg.ptr, msg.length);
		s.error_check(r);
		return s;
	}
	static public Session create_inbound_from(Account a, string identity_key, string one_time_key_msg) {
		auto s = new Session();
		char[] msg = one_time_key_msg.dup; // msg is destroyed!
		const r = olm_create_inbound_session_from(s.session, a.account,
			identity_key.ptr, identity_key.length,
			msg.ptr, msg.length);
		s.error_check(r);
		return s;
	}
	public @property string id() {
		char[] ret;
		ret.length = olm_session_id_length(this.session);
		const r = olm_session_id(this.session, ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret);
	}
	public bool matches_inbound(string one_time_key_msg) {
		char[] msg = one_time_key_msg.dup; // msg is destroyed!
		const r = olm_matches_inbound_session(this.session,
			msg.ptr, msg.length);
		error_check(r);
		return r == 1;
	}
	public bool matches_inbound_from(string identity_key, string one_time_key_msg) {
		char[] msg = one_time_key_msg.dup; // msg is destroyed!
		const r = olm_matches_inbound_session_from(this.session,
			identity_key.ptr, identity_key.length,
			msg.ptr, msg.length);
		error_check(r);
		return r == 1;
	}
	public string encrypt(string plaintext, out size_t msg_type) {
		const rnd_len = olm_encrypt_random_length(this.session);
		auto rnd_mem = read_random(rnd_len);
		msg_type = olm_encrypt_message_type(this.session);
		// TODO use enum for msg_type?
		error_check(msg_type);
		auto msg_len = olm_encrypt_message_length(this.session, plaintext.length);
		char[] ret;
		ret.length = msg_len;
		const r = olm_encrypt(this.session,
			plaintext.ptr, plaintext.length,
			rnd_mem.ptr, rnd_mem.length,
			ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret);
	}
	public string decrypt(size_t msg_type, string cypher) {
		char[] c = cypher.dup; // c is destroyed!
		const max_plain_len = olm_decrypt_max_plaintext_length(this.session,
			msg_type, c.ptr, c.length);
		error_check(max_plain_len);
		char[] ret;
		ret.length = max_plain_len;
		c = cypher.dup; // c is destroyed!
		const r = olm_decrypt(this.session, msg_type,
			c.ptr, c.length,
			ret.ptr, ret.length);
		error_check(r);
		return assumeUnique(ret[0..r]);
	}

	private void error_check(size_t x) {
		if (x == olm_error()) {
			auto errmsg = olm_session_last_error(this.session);
			throw new Exception(cstr2dstr(errmsg));
		}
	}
}

unittest {
	auto s = new Session();
	auto key = "foobar";
	auto p = s.pickle(key);
	auto s2 = Session.unpickle(key, p);
	assert(s.id == s2.id);

	size_t msg_type;
	auto plain = "Hello World!";
	auto cypher = s.encrypt(plain, msg_type);
	// TODO text decrypt
}

unittest {
	import std.json : parseJSON;

	// Setup account 1
	auto a1 = Account.create();
	string a1_id_key = parseJSON(a1.identity_keys)["curve25519"].str;
	a1.generate_one_time_keys(3);
	string a1_otk;
	foreach (k,v; parseJSON(a1.one_time_keys)["curve25519"].object) {
		a1_otk = v.str;
		break;
	}
	a1.mark_keys_as_published();

	// Setup account 2
	auto a2 = Account.create();
	string a2_id_key = parseJSON(a2.identity_keys)["curve25519"].str;
	a2.generate_one_time_keys(3);
	string a2_otk;
	foreach (k,v; parseJSON(a2.one_time_keys)["curve25519"].object) {
		a2_otk = v.str;
		break;
	}
	a2.mark_keys_as_published();

	/** Now a2 publishes his identity and one time keys,
      * such that a1 can encrypt a message for a2. */

	// exchange
	auto s1_out = Session.create_outbound(a1, a2_id_key, a2_otk);
	auto msg = "Hello World!";
	size_t msg_type;
	auto cipher = s1_out.encrypt(msg, msg_type);
	auto s2_in = Session.create_inbound(a2, cipher);
	assert(s1_out.id == s2_in.id);
	auto plain = s2_in.decrypt(msg_type, cipher);
	assert(plain == msg);
}
