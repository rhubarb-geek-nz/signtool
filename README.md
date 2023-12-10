# signtool
Tool to sign files using `REST` server. Uses the same arguments as Microsoft's `signtool.exe`.

This projects contains

- a service to run on a Windows machine with the Windows SDK
- a dotnet tool to run on Linux/macOS or other remote environment

The idea is that a program runs on the build machine that takes the same arguments as the original `signtool.exe`.

This forwards the request to a `REST` service which then runs the original `signtool.exe`.

The effect is that a `dotnet` build can sign dlls using the appropriate mechanisms.

The service is written in `ASP.NET Core` using the minimal API.

The tool is intended to be packaged as `nupkg` and restored from a `NuGet` repository.

The endpoint and credentials for the tool are in `signtool.runtimeconfig.json`.

The nupkg can be built on a `Windows` machine and then published in a `NuGet` repository. Linux machines or remote build servers can restore the tool for signing. The project `signtool` demonstrates signing itself on `Linux`.
