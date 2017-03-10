import std.stdio;

import matrix;

void main()
{
    auto c = new DummyClient("https://matrix.org");
    auto vs = c.versions();
    writeln(vs);
    c.login("mymatrixmailer", "XXXX");
    c.sync();
    writeln("success");
}
