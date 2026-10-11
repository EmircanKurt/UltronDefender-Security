#!/usr/bin/env bash
set -euo pipefail

# Includes full copyright/license texts from pinned packages, not only license links.
package_dir="${1:?Publish directory is required.}"
rid="${2:?Linux runtime identifier is required.}"
case "$rid" in linux-x64|linux-arm64) ;; *) exit 1 ;; esac
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
assets="$repo_dir/tools/Ultron.Linux.App/obj/project.assets.json"
package_cache="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project"]["restore"]["packagesPath"])' "$assets")"
license_dir="$package_dir/licenses"
mkdir -p -- "$license_dir"
copy_notice() {
    local source="$1" destination="$2"
    [[ -s "$source" ]] || { printf '%s\n' "Required license text is absent: $source" >&2; exit 1; }
    cp -- "$source" "$license_dir/$destination"
}
copy_notice "$repo_dir/docs/licenses/linux/Avalonia-MIT.txt" Avalonia-12.1.4-MIT.txt
copy_notice "$repo_dir/docs/licenses/linux/MicroCom-MIT.txt" MicroCom.Runtime-0.11.6-MIT.txt
copy_notice "$repo_dir/docs/licenses/linux/Tmds-DBus-MIT.txt" Tmds.DBus.Protocol-0.94.1-MIT.txt
copy_notice "$package_cache/skiasharp/3.119.4/LICENSE.txt" SkiaSharp-3.119.4-LICENSE.txt
copy_notice "$package_cache/skiasharp.nativeassets.linux/3.119.4/THIRD-PARTY-NOTICES.txt" SkiaSharp-native-3.119.4-NOTICES.txt
copy_notice "$package_cache/harfbuzzsharp/8.3.1.3/LICENSE.txt" HarfBuzzSharp-8.3.1.3-LICENSE.txt
copy_notice "$package_cache/harfbuzzsharp.nativeassets.linux/8.3.1.3/THIRD-PARTY-NOTICES.txt" HarfBuzzSharp-native-8.3.1.3-NOTICES.txt
for component in microsoft.extensions.logging.abstractions/8.0.2 microsoft.extensions.dependencyinjection.abstractions/8.0.2 system.io.pipelines/8.0.0; do
    name="${component//\//-}"
    copy_notice "$package_cache/$component/LICENSE.TXT" "$name-LICENSE.txt"
    copy_notice "$package_cache/$component/THIRD-PARTY-NOTICES.TXT" "$name-NOTICES.txt"
done
runtime_package="$package_cache/microsoft.netcore.app.runtime.$rid/8.0.31"
copy_notice "$runtime_package/LICENSE.TXT" dotnet-runtime-8.0.31-LICENSE.txt
copy_notice "$runtime_package/THIRD-PARTY-NOTICES.TXT" dotnet-runtime-8.0.31-NOTICES.txt
copy_notice "$repo_dir/docs/licenses/linux/README.md" SOURCE-PROVENANCE.md
(cd -- "$license_dir" && sha256sum -- ./*.txt ./*.md > SHA256SUMS)
printf '%s\n' 'Required full third-party license texts included.'
