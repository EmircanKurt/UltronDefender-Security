# Linux runtime license provenance

This directory vendors complete MIT copyright and permission texts for packages
that expose a license expression but do not include the text in the NuGet cache.
The source commits are taken from the pinned package nuspecs:

- Avalonia family 12.1.4: https://raw.githubusercontent.com/AvaloniaUI/Avalonia/2d79ba55fae1b1e71c69f93a668080c9029e6a31/licence.md
- MicroCom.Runtime 0.11.6: https://raw.githubusercontent.com/kekekeks/MicroCom/76785efcafd91b5902fd19dd11145f6dd655b7b4/LICENSE
- Tmds.DBus.Protocol 0.94.1: https://raw.githubusercontent.com/tmds/Tmds.DBus/b4a7fed0b878f74cb54f7cca84d2889af4e596ba/COPYING

The packaging collector also requires complete license and notice texts from the
content-hash-locked NuGet cache for SkiaSharp 3.119.4, HarfBuzzSharp 8.3.1.3,
their Linux native assets, Microsoft.Extensions.Logging.Abstractions 8.0.2,
Microsoft.Extensions.DependencyInjection.Abstractions 8.0.2, System.IO.Pipelines
8.0.0, and the selected Linux .NET runtime 8.0.31. It fails if a required text is
missing. Build-only and other-platform native assets are not claimed as shipped
Linux components. The actual archive must still be checked against its contents.

The archive retains separate texts and a SHA-256 license manifest under licenses/.
No dependency license is replaced by Ultron's own repository LICENSE.
