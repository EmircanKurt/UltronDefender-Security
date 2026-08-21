# 📜 THIRD-PARTY NOTICES & OPEN-SOURCE ATTRIBUTIONS

Ultron Defender Total Security utilizes or draws architectural inspiration from several open-source libraries, frameworks, and reference projects. We gratefully acknowledge the following contributions:

---

## 1. Runtime Libraries & Frameworks

### Microsoft .NET Runtime & Windows Desktop SDK
* **License:** MIT License
* **Copyright:** (c) .NET Foundation and Contributors
* **URL:** https://github.com/dotnet/runtime

### WPF UI (Lepo.iP / WPF-UI)
* **License:** MIT License
* **Copyright:** (c) Leszek Pomianowski and WPF UI Contributors
* **URL:** https://github.com/lepoco/wpfui

### Microsoft.Data.Sqlite / SQLitePCLRaw
* **License:** MIT License / Public Domain (SQLite)
* **Copyright:** (c) Microsoft Corporation and SQLite Development Team
* **URL:** https://github.com/dotnet/efcore

### Microsoft.Extensions.DependencyInjection & Logging
* **License:** MIT License
* **Copyright:** (c) Microsoft Corporation
* **URL:** https://github.com/dotnet/runtime

### Inno Setup (Jordan Russell / Martijn Laan)
* **License:** Inno Setup License (Modified BSD-like)
* **Copyright:** (c) 1997-2026 Jordan Russell, Martijn Laan
* **URL:** https://jrsoftware.org/isinfo.php

---

## 2. Architectural & Defensive Research References

The following open-source projects were studied during defensive engineering research to establish best practices for telemetry normalization, queue management, and scan safety:

* **Microsoft Windows Driver Samples (avscan & scanner):** MS-PL / MIT. (c) Microsoft Corporation.
* **KicomAV (k2pack & dual caching models):** GPL v2. (c) Hanul93 / Nurilab.
* **WHIDS (Gene rule correlation concepts):** Apache 2.0. (c) 0xrawsec.
* **Owlyshield (Novelty baseline correlation):** AGPL v3. (c) SitinCloud.
* **AkesoEDR (3-Tier Detection Architecture concepts):** Source-Available Research. (c) Derek Martin.
* **ClamAV (Decompression bomb guards):** GPL v2. (c) Cisco Systems, Inc. / Talos.

*(Note: Architectural ideas and defensive threat models were studied for clean-room engineering. No proprietary or GPL-incompatible binary code is linked into Ultron Defender binaries).*
