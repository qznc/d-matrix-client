module matrix;

import std.json;
import std.conv : to;
import std.array : array;
import std.algorithm : map;

import requests;

abstract class Client {
    private:
    string server_url;
    string access_token;
    string device_id;
    string user_id;
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

    public void sync() {
        // TODO timeout, since, next_batch
        import std.stdio;
        auto res = rq.get(server_url ~ "/_matrix/client/r0/sync",
                queryParams("set_presence", "offline",
                    "access_token", this.access_token));
        auto j = parseResponse(res);
        foreach(string k; j.object.byKey) {
            writeln(k, j[k]);
        }
    }

    abstract public void onRoomEvent() { }
}

final class DummyClient : Client {
    public this(string url) { super(url); }
    override public void onRoomEvent() { }
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
