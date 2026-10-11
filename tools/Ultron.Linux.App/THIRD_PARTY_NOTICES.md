# Linux preview third-party notices

The Ultron source linked into this preview remains under the repository's
`LICENSE`, which is included in the archive. The portable adapter and Linux shell
do not change that license.

The GUI depends on [Avalonia 12.1.4](https://www.nuget.org/packages/Avalonia/12.1.4),
including Avalonia Desktop, Fluent, Skia and their platform dependencies. Avalonia
is distributed under the [MIT license](https://github.com/AvaloniaUI/Avalonia/blob/master/licence.md).
Full copyright and permission texts are included under `licenses/`, not only
linked here. Pinned source commits for Avalonia, MicroCom and Tmds are recorded in
`licenses/SOURCE-PROVENANCE.md`. SkiaSharp, HarfBuzzSharp and Microsoft package
license/notice texts are taken from the content-hash-locked NuGet cache. The
collector refuses packaging when any required license text is absent.

The packaging collector explicitly copies the selected Linux .NET 8.0.31 runtime's
license and third-party notices; it does not assume publish includes them.
Microsoft.Extensions.Logging.Abstractions 8.0.2 uses the
[MIT license](https://www.nuget.org/packages/Microsoft.Extensions.Logging.Abstractions/8.0.2).

This notice is not a security efficacy or production-support claim. The archive is
an unsigned manual inspection preview with the limitations in `LINUX_PREVIEW.md`.
