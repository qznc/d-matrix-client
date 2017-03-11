import std.stdio;

import matrix.matrix;
import matrix.olm;

void main()
{
    ubyte major, minor, patch;
    olm_get_library_version(&major, &minor, &patch);
    writeln("olm ", major, ".", minor, ".", patch);

    auto c = new DummyClient("https://matrix.org");
    auto vs = c.versions();
    writeln(vs);
    c.login("mymatrixmailer", "XXXX");
    c.sync(100);
    c.sync(100);
    auto rid = c.createRoom(RoomPreset.trusted_private_chat);
    c.invite(rid, "@qznc:matrix.org");
    c.send(rid, "Welcome to my room");
    writeln("success");
}
