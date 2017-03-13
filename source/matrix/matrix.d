module matrix.matrix;

import std.json;
import std.conv : to, text;
import std.array : array;
import std.algorithm : map;

import requests;
import requests.utils : urlEncoded;

import matrix.olm;

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
    /// IDentifier of this device by server
    string device_id;
    /// Matrix user id, known after login
    string user_id;
    /// ID of the last sync
    string next_batch;
    Request rq;
    /// Account data for encryption with olm
    Account account = null;

    public this(string url) {
        this.server_url = url;
        //this.rq.verbosity = 2;
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
        this.device_id = j["device_id"].str;
        this.user_id = j["user_id"].str;
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
        if (this.next_batch)
            qp = queryParams("set_presence", "offline",
                "since", this.next_batch,
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
        this.next_batch = j["next_batch"].str;
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
                onJoinRoom(roomname, hc, nc);
                if ("timeline" in joined_room) {
                    // TODO limited, prev_batch
                    foreach (event; joined_room["timeline"]["events"].array)
                        onJoinTimelineEvent(roomname, event);
                }
                if ("state" in joined_room) {
                    foreach (event; joined_room["state"]["events"].array)
                        onJoinStateEvent(roomname, event);
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

    public void send(string roomname, string msg) {
        auto content = parseJSON("{\"msgtype\": \"m.text\"}");
        content["body"] = msg;
        string url = server_url ~ "/_matrix/client/r0/rooms/" ~ roomname
            ~ "/send/m.room.message/" ~ nextTransactionID()
            ~ "?access_token=" ~ urlEncoded(this.access_token);
        auto res = rq.exec!"PUT"(url, text(content));
        auto j = parseResponse(res);
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
     *  Requires path to file with private keys etc.
     *  Must be logged in, so we know the user id.
     *  If path exist, then load it and decrypt with key.
     *  Otherwise create new keys and store them there encrypted with key.
     **/
    public void enable_encryption(string key, string path) {
        import std.file;
        if (path.exists) {
            this.account = Account.unpickle(key, readText(path));
        } else {
            this.account = Account.create();
            path.write(this.account.pickle(key));
        }
        /* create payload for publishing keys to homeserver */
        assert (this.user_id); // must login first!
        const keys = parseJSON(this.account.identity_keys);
        JSONValue json = [
            "device_id": this.device_id,
            "user_id": this.user_id ];
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
                writeln(k,v);
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
        j["signatures"] = [user_id: ["ed25519:"~device_id: signature]];
    }
}

final class DummyClient : Client {
    import std.stdio;
    public this(string url) { super(url); }
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
