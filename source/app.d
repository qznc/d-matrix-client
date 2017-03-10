import std.stdio;

import matrix;

void main()
{
    auto c = new Client("https://matrix.org");
    auto vs = c.versions();
    writeln(vs);
    c.login("mymatrixmailer", "XXXX");
    writeln("success");
}
