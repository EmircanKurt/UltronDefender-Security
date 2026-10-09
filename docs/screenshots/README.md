# Interface previews

Current gallery: **9 October 2026**, source commit [`118e7cd`](https://github.com/EmircanKurt/UltronDefender-Security/tree/118e7cd38760ced1060c9b95505e4c0d04fb12bc), development [pull request #9](https://github.com/EmircanKurt/UltronDefender-Security/pull/9).

These PNGs are off-screen renders of real WPF controls, not photographs, AI-generated mockups or screenshots of deployed protection. The shell uses synthetic navigation commands with the actual sidebar item style. Test data supplies history, file paths, counts, time and CPU/RAM readings. None of these values demonstrates scan efficacy, performance or active protection.

| Preview | Render source | Size |
|---|---|---|
| [Light scan chooser](current/scan-light-preview.png) | `ClassicScanUiReviewTests`: light shell fixture | 1180 × 776 |
| [Dark scan chooser](current/scan-dark-preview.png) | `ClassicScanUiReviewTests`: dark shell fixture | 1180 × 776 |
| [Dark scanning view](current/scan-route-dark-preview.png) | `FlatRouteScanReviewTests`: finite dark fixture | 932 × 490 |
| [Light scanning view](current/scan-route-light-preview.png) | `FlatRouteScanReviewTests`: finite light fixture | 932 × 490 |

The route images show one animation frame. Responsive rendering and theme assertions are UI regressions, not deployed-service or malware tests. The application title bar, live GPU animation and installed service are outside these fixture captures.

The older image files in this directory are legacy assets, not the current Ultron interface. They are not included in the current README gallery. The existing shield logo is a branding asset, not a protection-status indicator.
