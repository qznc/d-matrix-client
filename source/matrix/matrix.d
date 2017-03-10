module matrix;

import std.json;
import std.conv : to;
import std.array : array;
import std.algorithm : map;

import requests;

void checkError(JSONValue j) {
    if ("error" in j) {
        import std.stdio;
        writeln(j);
        throw new MatrixError(
            j["errcode"].str ~" "~ j["error"].str);
    }
}

class Client {
    private string server_url;
    private Request rq;

    public this(string url) {
        this.server_url = url;
        this.rq.verbosity = 2;
    }

    public string[] versions() {
        auto res = rq.get(server_url ~ "/_matrix/client/versions");
        auto r = res.responseBody;
        auto j = parseJSON(r, JSONOptions.none);
        checkError(j);
        return j["versions"].array.map!"a.str".array;
    }

    public void login() {
        import std.stdio;
        auto res = rq.post(server_url ~ "/_matrix/client/r0/login", "");
        auto r = res.responseBody;
        writeln(r);
        writeln("login");
    }

    public void login(string name, string password) {
        import std.stdio;
        auto p = parseJSON("{}");
        p["type"] = "m.login.password";
        p["name"] = name;
        p["password"] = password;
        writeln("bla");
        writeln(p);
        auto res = rq.post(server_url ~ "/_matrix/client/r0/login", p.to!string, "application/json");
        auto r = res.responseBody;
        auto j = parseJSON(r, JSONOptions.none);
        checkError(j);
        writeln(r);
        writeln("login with pw");
    }
}

class MatrixError : Exception {
    public this(string msg) {
        super(msg);
    }
}
