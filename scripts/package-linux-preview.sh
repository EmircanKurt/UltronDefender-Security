#!/usr/bin/env bash
set -euo pipefail

# Must run on Linux after the actual Ubuntu native/headless/X11 checks pass.
# Packages a preview only; does not install a service, enable protection or upload assets.
if [[ "$(uname -s)" != "Linux" ]]; then
    printf '%s\n' 'Linux packaging requires an actual Linux host.' >&2
    exit 1
fi
rid="${1:-linux-x64}"
case "$rid" in linux-x64|linux-arm64) ;; *) printf '%s\n' 'Unsupported runtime identifier.' >&2; exit 1 ;; esac
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
package_dir="$(mktemp -d "${TMPDIR:-/tmp}/ultron-linux-preview-package.XXXXXXXX")"
output_dir="$repo_dir/artifacts/linux-preview-package"
mkdir -p -- "$output_dir"
cd -- "$repo_dir/tools/Ultron.Linux.App"
sdk_version="$(dotnet --version)"
if [[ "$sdk_version" != 10.* ]]; then
    printf '%s\n' "A stable .NET 10 SDK is required; selected SDK: $sdk_version" >&2
    exit 1
fi
dotnet publish "$repo_dir/tools/Ultron.Linux.App/Ultron.Linux.App.csproj" -c Release -r "$rid" \
    --self-contained true -p:RestoreLockedMode=true -p:PublishSingleFile=false -p:PublishTrimmed=false -warnaserror -o "$package_dir"
cp -- "$repo_dir/docs/architecture/LINUX_PREVIEW.md" "$package_dir/LINUX_PREVIEW.md"
cp -- "$repo_dir/LICENSE" "$package_dir/LICENSE"
cp -- "$repo_dir/tools/Ultron.Linux.App/THIRD_PARTY_NOTICES.md" "$package_dir/THIRD_PARTY_NOTICES.md"
bash "$repo_dir/scripts/collect-linux-preview-licenses.sh" "$package_dir" "$rid"
cp -- "$repo_dir/scripts/linux/install.py" "$package_dir/install.py"
cp -- "$repo_dir/scripts/linux/uninstall.py" "$package_dir/uninstall.py"
source_sha="${GITHUB_SHA:-local-not-git-verified}"
if [[ "$source_sha" != local-not-git-verified && ! "$source_sha" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s\n' 'Invalid source commit identity.' >&2
    exit 1
fi
printf '%s\n' "$source_sha" > "$package_dir/SOURCE-COMMIT.txt"
(cd -- "$package_dir" && find . -type f ! -name FILE-SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > FILE-SHA256SUMS)
archive="$output_dir/UltronDefender-Linux-0.1.0-preview-$rid.tar.gz"
if [[ -e "$archive" ]]; then
    printf '%s\n' "Refusing to overwrite existing preview archive: $archive" >&2
    exit 1
fi
tar -C "$package_dir" -czf "$archive" .
(cd -- "$output_dir" && sha256sum -- "$(basename -- "$archive")" > "$(basename -- "$archive").sha256")
printf '%s\n' "$archive"
printf '%s\n' "Temporary publish directory retained for review: $package_dir"
