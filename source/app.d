import std.stdio;

import matrix;

void main()
{
    auto c = new DummyClient("https://matrix.org");
    auto vs = c.versions();
    writeln(vs);
    c.login("mymatrixmailer", "XXXX");
    c.sync(100);
    c.sync(100);
    c.send("!iDkpVrMDXDLxWwprSd:matrix.org", "test via D");
    writeln("success");
}
