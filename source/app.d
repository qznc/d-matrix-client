import std.stdio;

import matrix.matrix;
import matrix.olm;

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
    foreach (r; c.rooms) {
        c.send(r, "yolo!");
    }
    c.setPresence(Presence.offline, "Hello World!");
    c.sync(100);
    c.saveState();
    auto rid = c.createRoom(RoomPreset.trusted_private_chat);
    c.invite(rid, "@qznc:matrix.org");
    c.send(rid, "Welcome to my room");
    c.logout();
    writeln("success");
}
