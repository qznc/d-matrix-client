module matrix.matrix;

import std.json;
import std.conv : to, text;
import std.array : array;
import std.algorithm : map, countUntil, canFind;

import requests;
import requests.utils : urlEncoded;

import matrix.olm : Session, Account;
import matrix.inbound_group : InboundGroupSession;
import matrix.outbound_group : OutboundGroupSession;

enum RoomPreset {
    /// Joining requires an invite
    private_chat,
    /// Joining requires an invite, everybody is admin
    trusted_private_chat,
    /// Anybody can join
    public_chat
}

abstract class Client {
    private:
    /// Server, e.g. "https://matrix.org"
    string server_url;
    /// Token received after successful login
    string access_token;
    /// Generate a transaction ID unique across requests with the same access token
    long tid;
    Request rq;
    /// Account data for encryption with olm
    Account account = null;
    /// State of the client, which should be preserved
    JSONValue state;
    /// Path where to store the state permanently
    string state_path;
    /// Encryption key used for all account and session serializations
    string key;

    public this(string url, string state_path) {
        this.server_url = url;
        this.state_path = state_path;
        updateFromStatePath();
        //this.rq.verbosity = 1;
    }

    import std.file;

    private void updateFromStatePath() {
        if (state_path.exists) {
            string raw = cast(string) read(state_path);
            this.state = parseJSON(raw);
            assert("user_id" in state);
            assert("device_id" in state);
            assert("next_batch" in state);
        } else {
            /* ensure basic fields exist */
            /// Identifier of this device by server
            this.state["user_id"] = "";
            /// Matrix user id, known after login
            this.state["device_id"] = "";
            /// ID of the last sync
            this.state["next_batch"] = "";
            /// We must keep track of rooms
            this.state["rooms"] = parseJSON("{}");
            /// We must keep track of other users
            this.state["users"] = parseJSON("{}");
        }
    }

    public void saveState() const @safe {
        this.state_path.write(state.toPrettyString());
    }

    public string[] versions() {
        auto res = rq.get(server_url ~ "/_matrix/client/versions");
        auto j = parseResponse(res);
        return j["versions"].array.map!"a.str".array;
    }

    public void login(string name, string password) {
        auto payload = "{ \"type\": \"m.login.password\", \"user\": \""~name~"\", \"password\": \""~password~"\" }";
        /* Creating a JSONValue object would be safer, but matrix.org
         * requires a fixed order for the keys. */
        auto res = rq.post(server_url ~ "/_matrix/client/r0/login",
                payload, "application/json");
        auto j = parseResponse(res);
        this.access_token = j["access_token"].str;
        if (state["device_id"].str == "")
            this.state["device_id"] = j["device_id"];
        this.state["user_id"] = j["user_id"];
        // TODO store and use refresh_token
    }

    public void logout() {
        auto res = rq.post(server_url ~ "/_matrix/client/r0/logout"
            ~ "?access_token=" ~ urlEncoded(this.access_token));
        auto j = parseResponse(res);
        this.access_token = "";
    }

    public void sync(int timeout) {
        auto qp = queryParams("set_presence", "offline",
            "timeout", timeout,
            "access_token", this.access_token);
        if (state["next_batch"].str != "")
            qp = queryParams("set_presence", "offline",
                "since", state["next_batch"].str,
                "timeout", timeout,
                "access_token", this.access_token);
        auto res = rq.get(server_url ~ "/_matrix/client/r0/sync", qp);
        auto j = parseResponse(res);
        /* sync room states */
        if ("rooms" in j) {
            syncRoomState(j["rooms"]);
        }
        /* sync presence states */
        if ("presence" in j && "events" in j["presence"]) {
            auto events = j["presence"]["events"].array;
            foreach(JSONValue e; events) {
                onPresenceEvent(e);
            }
        }
        /* sync account_data states */
        if ("account_data" in j && "events" in j["account_data"]) {
            auto events = j["account_data"]["events"].array;
            foreach(JSONValue e; events) {
                onSyncAccountDataEvent(e);
            }
        }
        /* sync account_data states */
        if ("to_device" in j) {
            auto events = j["to_device"]["events"].array;
            foreach(JSONValue e; events) {
                writeln("TO_DEVICE ", e);
            }
        }
        if (state["next_batch"].str == "") {
            /* announce this device */
            JSONValue ann = [
                "device_id": state["device_id"],
                "rooms": parseJSON("[]"),
            ];
            foreach (room_id, j; state["rooms"].object) {
                if ("encrypted" !in j.object)
                    continue;
                ann["rooms"].array ~= JSONValue(room_id);
            }
        }
        state["next_batch"] = j["next_batch"];
    }

    private void syncRoomState(JSONValue json) {
        if ("invite" in json) {
            foreach (string roomname, JSONValue left_room; json["invite"]) {
                onInviteRoom(roomname);
                foreach (JSONValue event; left_room["invite_state"]["events"].array)
                    onInviteEvent(roomname, event);
            }
        }
        if ("leave" in json) {
            foreach (string roomname, JSONValue left_room; json["leave"]) {
                assert (roomname in state["rooms"]);
                state["rooms"][roomname] = null;
                onLeaveRoom(roomname, left_room);
                if ("timeline" in left_room) {
                    // TODO limited, prev_batch
                    foreach (event; left_room["timeline"]["events"].array)
                        onLeaveTimelineEvent(roomname, event);
                }
                if ("state" in left_room) {
                    foreach (event; left_room["state"]["events"].array)
                        onLeaveStateEvent(roomname, event);
                }
            }
        }
        if ("join" in json) {
            foreach (string roomname, JSONValue joined_room; json["join"]) {
                auto un = joined_room["unread_notifications"];
                ulong hc, nc;
                if ("highlight_count" in un)
                    hc = un["highlight_count"].integer;
                if ("notification_count" in un)
                    nc = un["notification_count"].integer;
                if (roomname !in state["rooms"])
                    state["rooms"][roomname] = parseJSON("{\"members\": {}}");
                onJoinRoom(roomname, hc, nc);
                if ("timeline" in joined_room) {
                    // TODO limited, prev_batch
                    foreach (event; joined_room["timeline"]["events"].array) {
                        auto sender = event["sender"].str;
                        if (event["type"].str == "m.room.member") {
                            seenUserIdInRoom(event["sender"], roomname);
                            state["rooms"][roomname]["members"][sender] = parseJSON("{}");
                            continue;
                        }
                        if (event["type"].str == "m.room.encryption") {
                            state["rooms"][roomname]["encrypted"] = true;
                            // only support megolm
                            assert (event["content"]["algorithm"].str == "m.megolm.v1.aes-sha2");
                            writeln(sender, " enabled encryption for ", roomname);

                            continue;
                        }
                        onJoinTimelineEvent(roomname, event);
                    }
                }
                if ("state" in joined_room) {
                    foreach (event; joined_room["state"]["events"].array) {
                        auto sender = event["sender"].str;
                        if (event["type"].str == "m.room.name") {
                            state["rooms"][roomname]["name"]
                                = event["content"]["name"].str;
                            continue;
                        }
                        if (event["type"].str == "m.room.topic") {
                            state["rooms"][roomname]["topic"]
                                = event["content"]["topic"].str;
                            continue;
                        }
                        if (event["type"].str == "m.room.member") {
                            seenUserIdInRoom(event["sender"], roomname);
                            state["rooms"][roomname]["members"][sender] = parseJSON("{}");
                            continue;
                        }
                        if (event["type"].str == "m.room.encryption") {
                            state["rooms"][roomname]["encrypted"] = true;
                            // only support megolm
                            assert (event["content"]["algorithm"].str == "m.megolm.v1.aes-sha2");
                            writeln(sender, " enabled encryption for ", roomname);
                            continue;
                        }
                        onJoinStateEvent(roomname, event);
                    }
                }
                if ("account_data" in joined_room) {
                    foreach (event; joined_room["account_data"]["events"].array)
                        onJoinAccountDataEvent(roomname, event);
                }
                if ("ephemeral" in joined_room) {
                    foreach (event; joined_room["ephemeral"]["events"].array)
                        onEphemeralEvent(roomname, event);
                }
            }
        }
    }

    private void seenUserIdInRoom(JSONValue user_id, string room_id) {
        if (user_id.str !in state["rooms"][room_id]["members"]) {
            state["rooms"][room_id]["members"][user_id.str] = parseJSON("{}");
        }
        if (user_id.str !in state["users"]) {
            state["users"][user_id.str] = parseJSON("{}");
        }
    }

    abstract public void onInviteRoom(const string name);
    abstract public void onInviteEvent(const string name, const JSONValue v);
    abstract public void onLeaveRoom(const string name, const JSONValue v);
    abstract public void onJoinRoom(const string name, ulong highlight_count, ulong notification_count);
    abstract public void onLeaveTimelineEvent(const string name, const JSONValue v);
    abstract public void onLeaveStateEvent(const string name, const JSONValue v);
    abstract public void onJoinTimelineEvent(const string name, const JSONValue v);
    abstract public void onJoinStateEvent(const string name, const JSONValue v);
    abstract public void onJoinAccountDataEvent(const string name, const JSONValue v);
    abstract public void onSyncAccountDataEvent(const JSONValue v);
    abstract public void onEphemeralEvent(const string name, const JSONValue v);
    abstract public void onPresenceEvent(const JSONValue v);
    abstract public void onAccountDataUpdate(const string type, const string key, const JSONValue value);

    private string nextTransactionID() {
        scope(exit) this.tid += 1;
        return text(this.tid);
    }

    private void fetchDeviceKeys(string roomname) {
        auto q = parseJSON("{\"device_keys\":{}}");
        foreach (user_id, j; state["rooms"][roomname]["members"].object) {
            q["device_keys"][user_id] = parseJSON("{}");
        }
        string url = server_url ~ "/_matrix/client/unstable/keys/query"
            ~ "?access_token=" ~ urlEncoded(this.access_token);
        auto res = rq.post(url, text(q));
        auto j = parseResponse(res);
        check_signature(j);
        foreach(user_id, j2; j["device_keys"].object) {
            if (user_id !in state["users"])
                state["users"][user_id] = parseJSON("{}");
            foreach(device_id, j3; j2.object) {
                check_signature(j3);
                // FIXME match user_id-device_id against known information
                // FIXME for known devices match ed25519 key
                if (device_id !in state["users"][user_id]) {
                    state["users"][user_id][device_id] = parseJSON("{}");
                }
                foreach(method, key; j3["keys"].object) {
                    auto i = method.countUntil(":");
                    // FIXME what if already in there?
                    state["users"][user_id][device_id][method[0..i]] = key;
                }
            }
        }
    }

    public void send(string roomname, string msg) {
        if ("encrypted" in state["rooms"][roomname]) {
            fetchDeviceKeys(roomname);
            OutboundGroupSession outbound;
            if ("enc_outbound" in state["rooms"][roomname]) {
                outbound = OutboundGroupSession.unpickle(this.key, state["rooms"][roomname]["enc_outbound"].str);
            } else {
                outbound = new OutboundGroupSession();
                state["rooms"][roomname]["enc_outbound"] = outbound.pickle(this.key);
            }
            // FIXME check if outbound requires rotation
            sendSessionKeyAround(roomname, outbound);
            JSONValue payload = [
                "type": "m.text",
                "content": msg,
                "room_id": roomname
            ];
            auto cipher = outbound.encrypt(text(payload));
            JSONValue content = [
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": outbound.session_key,
                "ciphertext": cipher,
                "session_id": outbound.session_id,
                "device_id": state["device_id"].str,
            ];
            string url = server_url ~ "/_matrix/client/r0/rooms/"
                ~ roomname ~ "/send/m.room.encrypted/" ~ nextTransactionID()
                ~ "?access_token=" ~ urlEncoded(this.access_token);
            auto res = rq.exec!"PUT"(url, text(content));
            auto j = parseResponse(res);
        } else { /* sending unencrypted */
            auto content = parseJSON("{\"msgtype\": \"m.text\"}");
            content["body"] = msg;
            string url = server_url ~ "/_matrix/client/r0/rooms/" ~ roomname
                ~ "/send/m.room.message/" ~ nextTransactionID()
                ~ "?access_token=" ~ urlEncoded(this.access_token);
            auto res = rq.exec!"PUT"(url, text(content));
            auto j = parseResponse(res);
        }
    }

    private void sendSessionKeyAround(string room_id, OutboundGroupSession outbound) {
        auto s_id = outbound.session_id;
        auto s_key = outbound.session_key;
        auto device_id = state["device_id"].str;
        /* store these details as an inbound session, just as it would when receiving them via an m.room_key event */
        if (device_id !in state["rooms"][room_id]["members"][state["user_id"].str]) {
            auto inb = InboundGroupSession.init(s_key);
            JSONValue j = [
                "session_key": s_key,
                "enc_inbound": inb.pickle(this.key),
            ];
            auto uid = state["user_id"].str;
            assert (device_id !in state["rooms"][room_id]["members"][uid]);
            state["rooms"][room_id]["members"][uid][device_id] = j;
        }
        createOlmSessions(state["rooms"][room_id]["members"].object.byKey.array);
        /* send session key to all other devices in the room */
        foreach (user_id, j; state["rooms"][room_id]["members"].object) {
            foreach (string device_id, j2; j.object) {
                JSONValue j = [
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "room_id": room_id,
                    "session_id": s_id,
                    "session_key": s_key,
                ];
                sendToDevice(user_id, device_id, text(j));
            }
        }
    }

    private void createOlmSessions(const string[] users) {
        /* claim one time keys */
        JSONValue payload = ["one_time_keys": parseJSON("{}")];
        foreach (user_id, j; state["users"].object) {
            if (!users.canFind(user_id))
                continue;
            payload["one_time_keys"][user_id] = parseJSON("{}");
            foreach (dev_id, j2; j.object) {
                payload["one_time_keys"][user_id][dev_id] = "signed_curve25519";
            }
        }
        string url = server_url ~ "/_matrix/client/unstable/keys/claim"
            ~ "?access_token=" ~ urlEncoded(this.access_token);
        auto res = rq.post(url, text(payload), "application/json");
        /* create sessions from one time keys */
        auto j = parseResponse(res);
        foreach (user_id, j; j["one_time_keys"].object) {
            foreach (device_id, j2; j.object) {
                foreach (s_key_id, j3; j2.object) {
                    import std.algorithm : startsWith;
                    assert (s_key_id.startsWith("signed_curve25519:"));
                    check_signature(j3);
                    auto dev_key = j3["key"].str;
                    auto identity_key = state["users"][user_id][device_id]["ed25519"].str;
                    auto session = Session.create_outbound(this.account, identity_key, dev_key);
                    state["users"][user_id][device_id]["enc_session"] = session.pickle(this.key);
                }
            }
        }
    }

    private void sendToDevice(string user_id, string device_id, string msg) {
        if (device_id !in state["users"][user_id])
            return; // TODO throw, instead of silent drop?
        if ("enc_session" !in state["users"][user_id][device_id])
            return; // TODO throw, instead of silent drop?
        auto session = Session.unpickle(this.key,
                state["users"][user_id][device_id]["enc_session"].str);
        ulong msg_type;
        auto cipher = session.encrypt(msg, msg_type);
        // FIXME msg_type?!
        string url = server_url ~ "/_matrix/client/unstable/sendToDevice/"
            ~ "/m.room.encrypted/" ~ nextTransactionID()
            ~ "?access_token=" ~ urlEncoded(this.access_token);
        auto res = rq.exec!"PUT"(url, cipher);
    }

    private string[] devicesOfRoom(string room_id) {
        string[] ret;
        foreach (user_id, j; state["rooms"][room_id]["members"].object) {
            foreach (string device_id, j2; j.object) {
                ret ~= device_id;
            }
        }
        return ret;
    }

    private void check_signature(JSONValue j) {
        // FIXME actually implement check
        /* if signature check fails, mark the failing device as 'evil' */
    }

    /** Create a new room on the homeserver
     *  Returns: id of the room
     */
    public string createRoom(RoomPreset p) {
        JSONValue content = parseJSON("{}");
        content["preset"] = text(p);
        string url = server_url ~ "/_matrix/client/r0/createRoom"
            ~ "?access_token=" ~ urlEncoded(this.access_token);
        auto payload = text(content);
        auto res = rq.post(url, payload, "application/json");
        auto j = parseResponse(res);
        return j["room_id"].str;
    }

    public void invite(string roomid, string userid) {
        JSONValue content = parseJSON("{}");
        content["user_id"] = userid;
        string url = server_url ~ "/_matrix/client/r0/rooms/"
            ~ roomid ~ "/invite"
            ~ "?access_token=" ~ urlEncoded(this.access_token);
        auto payload = text(content);
        auto res = rq.post(url, payload, "application/json");
        auto j = parseResponse(res);
    }

    /** Enables encryption
     *  Requires key because we always store stuff locked up.
     *  Must be logged in, so we know the user id.
     *  If path exist, then load it and decrypt with key.
     *  Otherwise create new keys and store them there encrypted with key.
     **/
    public void enable_encryption(string key) {
        this.key = key;
        if ("encrypted_account" in state) {
            this.account = Account.unpickle(key, state["encrypted_account"].str);
        } else {
            this.account = Account.create();
            state["encrypted_account"] = account.pickle(key);
        }
        /* create payload for publishing keys to homeserver */
        assert (this.access_token); // must login first!
        const keys = parseJSON(this.account.identity_keys);
        const device_id = state["device_id"].str;
        JSONValue json = [
            "device_id": device_id,
            "user_id": state["user_id"].str ];
        json["algorithms"] = ["m.olm.v1.curve25519-aes-sha2",
            "m.megolm.v1.aes-sha2"];
        json["keys"] = [
            "curve25519:"~device_id: keys["curve25519"].str,
            "ed25519:"~device_id: keys["ed25519"].str
        ];
        sign_json(json);
        /* actually publish keys */
        auto payload = text(json);
        auto res = rq.post(server_url ~ "/_matrix/client/unstable/keys/upload"
                ~ "?access_token=" ~ urlEncoded(this.access_token),
                payload, "application/json");
        auto j = parseResponse(res);
        uploadOneTimeKeys(j);
    }

    /** Uploads more one time keys, if necessary */
    public void uploadOneTimeKeys() {
        auto res = rq.post(server_url ~ "/_matrix/client/unstable/keys/upload"
                ~ "?access_token=" ~ urlEncoded(this.access_token),
                "{}", "application/json");
        auto j = parseResponse(res);
        uploadOneTimeKeys(j);
    }

    private void uploadOneTimeKeys(JSONValue currently) {
        ulong otkeys_on_server;
        ulong max_otkeys_on_server = this.account.max_number_of_one_time_keys/2;
        if ("one_time_key_counts" in currently) {
            foreach(k,v; currently["one_time_key_counts"].object) {
                writeln("counting one time keys", k, v); // TODO
            }
        }
        if (otkeys_on_server >= max_otkeys_on_server)
            return;
        /* Generate new keys */
        auto diff = max_otkeys_on_server - otkeys_on_server;
        this.account.generate_one_time_keys(diff);
        auto keys = parseJSON(this.account.one_time_keys());
        JSONValue allkeys = ["one_time_keys": parseJSON("{}")];
        foreach(kid,key; keys["curve25519"].object) {
            JSONValue j = ["key": key];
            sign_json(j);
            allkeys["one_time_keys"]["signed_curve25519:"~kid] = j;
        }
        /* upload */
        auto payload = text(allkeys);
        auto res = rq.post(server_url ~ "/_matrix/client/unstable/keys/upload"
                ~ "?access_token=" ~ urlEncoded(this.access_token),
                payload, "application/json");
        auto j = parseResponse(res);
        this.account.mark_keys_as_published();
    }

    private void sign_json(JSONValue j) {
        /* D creates Canonical JSON as specified by Matrix */
        auto raw = text(j);
        auto signature = this.account.sign(raw);
        auto user_id = state["user_id"].str;
        auto device_id = state["device_id"].str;
        j["signatures"] = [user_id: ["ed25519:"~device_id: signature]];
    }

    public @property string[] rooms() {
        string[] ret;
        foreach (roomname, v; state["rooms"].object)
            ret ~= roomname;
        return ret;
    }
}

final class DummyClient : Client {
    import std.stdio;
    public this(string url, string state_path) { super(url, state_path); }
    override public void onInviteRoom(const string name)
    {
        writeln("invite "~name~" ...");
    }
    override public void onInviteEvent(const string name, const JSONValue v)
    {
        writeln("invite event "~name~" ...");
    }
    override public void onLeaveRoom(const string name, const JSONValue v)
    {
        writeln("leave "~name~" ...");
    }
    override public void onJoinRoom(const string name, ulong highlight_count,   ulong notification_count)
    {
        writeln("join ", name, " ", highlight_count, " ", notification_count);
    }
    override public void onJoinTimelineEvent(const string name, const JSONValue v)
    {
        writeln("join timeline ", name, " ", v);
    }
    override public void onLeaveTimelineEvent(const string name, const JSONValue v)
    {
        writeln("leave timeline ", name, " ", v);
    }
    override public void onEphemeralEvent(const string name, const JSONValue v)
    {
        writeln("ephemeral ", name, " ", v);
    }
    override public void onJoinStateEvent(const string name, const JSONValue v)
    {
        writeln("join state ", name, " ", v);
    }
    override public void onLeaveStateEvent(const string name, const JSONValue v)
    {
        writeln("leave state ", name, " ", v);
    }
    override public void onJoinAccountDataEvent(const string name, const JSONValue v)
    {
        writeln("join account data ", name, " ", v);
    }
    override public void onSyncAccountDataEvent(const JSONValue v)
    {
        writeln("sync account data ", v);
    }
    override public void onPresenceEvent(const JSONValue v)
    {
        writeln("presence event ", v);
    }
    override public void onAccountDataUpdate(const string type, const string key, const JSONValue value)
    {
        writeln("account data update "~type~"  "~key~": ...");
    }
}

/* Convert a raw response into JSON
 * and check for a Matrix error */
JSONValue parseResponse(Response res) {
    auto r = res.responseBody;
    auto j = parseJSON(r, JSONOptions.none);
    if ("error" in j)
        throw new MatrixError(
            j["errcode"].str ~" "~ j["error"].str);
    return j;
}

/* When the Matrix server sends an error message */
class MatrixError : Exception {
    public this(string msg) {
        super(msg);
    }
}
