import std.stdio;
import std.json;

import matrix.matrix;
import matrix.olm;

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
        //writeln("join ", name, " ", highlight_count, " ", notification_count);
    }
    override public void onJoinTimelineEvent(const string name, const JSONValue v)
    {
        if (v["type"].str == "m.room.create") return;
        if (v["type"].str == "m.room.join_rules") return;
        if (v["type"].str == "m.room.guest_access") return;
        if (v["type"].str == "m.room.history_visibility") return;
        if (v["type"].str == "m.room.power_levels") return;
        if (v["type"].str == "m.room.message") {
            assert(v["content"]["msgtype"].str == "m.text");
            writeln(name, " ", v["sender"].str, ": ", v["content"]["body"].str);
            return;
        }
        writeln("join timeline ", name, " ", v["type"], " ", v);
    }
    override public void onLeaveTimelineEvent(const string name, const JSONValue v)
    {
        writeln("leave timeline ", name, " ", v);
    }
    override public void onEphemeralEvent(const string name, const JSONValue v)
    {
        if (v["type"].str == "m.typing") return;
        if (v["type"].str == "m.receipt") return;
        writeln("ephemeral ", name, " ", v);
    }
    override public void onJoinStateEvent(const string name, const JSONValue v)
    {
        if (v["type"].str == "m.room.create") return;
        if (v["type"].str == "m.room.join_rules") return;
        if (v["type"].str == "m.room.guest_access") return;
        if (v["type"].str == "m.room.history_visibility") return;
        if (v["type"].str == "m.room.power_levels") return;
        writeln("join state ", name, " ", v["type"].str, " ", v);
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
        if (v["type"].str == "m.push_rules") return;
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


void main()
{
    ubyte major, minor, patch;
    olm_get_library_version(&major, &minor, &patch);
    writeln("olm ", major, ".", minor, ".", patch);

    auto c = new DummyClient("https://matrix.org", "matrix.state");
    auto vs = c.versions();
    writeln(vs);
    c.login("mymatrixmailer", "XXXX");
    c.setPresence(Presence.online, "Hello World!");
    c.enable_encryption("foo");
    c.sync(100);
    c.saveState();
    writeln("ROOMS: ", c.rooms);
    foreach (r; c.rooms) {
        c.send(r, "yolo!");
    }
    c.setPresence(Presence.offline, "Hello World!");
    c.sync(100);
    c.saveState();
    //c.sync(100);
    /*
    auto rid = c.createRoom(RoomPreset.trusted_private_chat);
    c.invite(rid, "@qznc:matrix.org");
    c.send(rid, "Welcome to my room");
    */
    c.logout();
    writeln("success");
}
