module matrix;

import std.json;
import std.conv : to, text;
import std.array : array;
import std.algorithm : map;

import requests;

abstract class Client {
    private:
    /// Server, e.g. "https://matrix.org"
    string server_url;
    /// Token received after successful login
    string access_token;
    /// Identifier of this device by server
    string device_id;
    /// Matrix user id, known after login
    string user_id;
    /// ID of the last sync
    string next_batch;
    Request rq;

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
        if ("rooms" in j)
            foreach(string k, JSONValue v; j["rooms"]) {
                switch (k) {
                    case "invite":
                        auto iv = j["rooms"]["invite"];
                        foreach (string roomname, JSONValue v; iv)
                            onInviteRoom(roomname, v);
                        break;
                    case "leave":
                        auto iv = j["rooms"]["leave"];
                        foreach (string roomname, JSONValue v; iv)
                            onLeaveRoom(roomname, v);
                        break;
                    case "join":
                        auto iv = j["rooms"]["join"];
                        foreach (string roomname, JSONValue v; iv)
                            onJoinRoom(roomname, v);
                        break;
                    default:
                        throw new Exception("unknown room event: "~k);
                }
            }
        //import std.stdio;
        //foreach (string k, JSONValue v; j)
        //    writeln(k);
        this.next_batch = j["next_batch"].str;
    }

    abstract public void onInviteRoom(const string name, const JSONValue v);
    abstract public void onLeaveRoom(const string name, const JSONValue v);
    abstract public void onJoinRoom(const string name, const JSONValue v);
}

final class DummyClient : Client {
    public this(string url) { super(url); }
    override public void onInviteRoom(const string name, const JSONValue v)
    {
        import std.stdio;
        writeln("invite "~name~"  "~text(v));
    }
    override public void onLeaveRoom(const string name, const JSONValue v)
    {
        import std.stdio;
        writeln("leave "~name~"  "~text(v));
    }
    override public void onJoinRoom(const string name, const JSONValue v)
    {
        import std.stdio;
        writeln("join "~name~"  "~text(v));
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
