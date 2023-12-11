# signtool
Tool to sign files using `REST` server.

Uses the same arguments as Microsoft's `signtool`.

Configuration is in an XML file at `$HOME/.local/share/rhubarb-geek-nz.signtool/signtool.config`.

```
<SignTool>
        <Endpoint>https://localhost:5001/signtool</Endpoint>
        <Authorization>Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==</Authorization>
</SignTool>
```
