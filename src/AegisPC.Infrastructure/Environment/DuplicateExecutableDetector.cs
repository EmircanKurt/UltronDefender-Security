using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using AegisPC.Contracts.Services;
using AegisPC.Core.Models;
using Microsoft.Extensions.Logging;

namespace AegisPC.Infrastructure.Platform
{
    /// <summary>
    /// Klasör ağacında birden çok UltronDefender.exe / AegisPC.exe derleme/yayın kopyası varsa tespit eder
    /// ve kullanıcıyı en güncel konuma yönlendirir (eski ikili sürüm karışıklığını önler).
    /// </summary>
    public class DuplicateExecutableDetector : IDuplicateExecutableDetector
    {
        private readonly ILogger<DuplicateExecutableDetector>? _logger;

        public DuplicateExecutableDetector(ILogger<DuplicateExecutableDetector>? logger = null)
        {
            _logger = logger;
        }

        public DuplicateExecutableResult CheckForDuplicates(string? searchRoot = null, string? currentExePath = null)
        {
            string runningExe = currentExePath ?? Environment.ProcessPath ?? string.Empty;

            var result = new DuplicateExecutableResult
            {
                RunningExecutablePath = runningExe,
                RecommendedExecutablePath = runningExe,
                HasDuplicates = false
            };

            string root = searchRoot ?? AppDomain.CurrentDomain.BaseDirectory;
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                return result;
            }

            try
            {
                var candidates = new List<FileInfo>();

                // Mevcut dizin ve üst klasörleri tara (maksimum 2 seviye yukarı)
                var currentDir = new DirectoryInfo(root);
                var searchDirs = new List<DirectoryInfo> { currentDir };

                if (currentDir.Parent != null)
                {
                    searchDirs.Add(currentDir.Parent);
                    if (currentDir.Parent.Parent != null)
                    {
                        searchDirs.Add(currentDir.Parent.Parent);
                    }
                }

                var targetFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "UltronDefender.exe",
                    "AegisPC.exe"
                };

                foreach (var sDir in searchDirs)
                {
                    try
                    {
                        var files = sDir.GetFiles("*.exe", SearchOption.AllDirectories)
                            .Where(f => targetFileNames.Contains(f.Name) &&
                                        !f.FullName.Contains(@"\obj\", StringComparison.OrdinalIgnoreCase));

                        candidates.AddRange(files);
                    }
                    catch { /* İzin verilmeyen alt klasörleri atla */ }
                }

                // Tekilleştir
                var distinctFiles = candidates
                    .GroupBy(f => f.FullName, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .ToList();

                if (distinctFiles.Count > 1)
                {
                    result.HasDuplicates = true;
                    result.DuplicateExecutablePaths = distinctFiles.Select(f => f.FullName).ToList();

                    // En güncel olanı bul (FileVersion ve LastWriteTime)
                    var bestCandidate = distinctFiles
                        .OrderByDescending(f => GetFileVersion(f.FullName))
                        .ThenByDescending(f => f.LastWriteTimeUtc)
                        .First();

                    result.RecommendedExecutablePath = bestCandidate.FullName;

                    bool isRunningOutdated = !string.IsNullOrEmpty(runningExe) &&
                        !string.Equals(runningExe, bestCandidate.FullName, StringComparison.OrdinalIgnoreCase);

                    if (isRunningOutdated)
                    {
                        result.AdvisoryMessage = $"UYARI: Çalıştırılan Ultron Defender sürümü güncel olmayabilir. Algılanan en güncel konum: {bestCandidate.FullName}";
                        _logger?.LogWarning("Eski veya yinelenen ikili yürütüldü: {Running}. Önerilen güncel ikili: {Best}",
                            runningExe, bestCandidate.FullName);
                    }
                    else
                    {
                        result.AdvisoryMessage = $"Bilgi: Sistemde {distinctFiles.Count} adet Ultron Defender kopyası bulundu. Şu an en güncel sürüm çalışıyor: {bestCandidate.FullName}";
                        _logger?.LogInformation("Birden çok kopya tespit edildi, çalışan sürüm güncel: {Best}", bestCandidate.FullName);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Yinelenen ikili tespiti sırasında hata oluştu.");
            }

            return result;
        }

        private static Version GetFileVersion(string filePath)
        {
            try
            {
                var info = FileVersionInfo.GetVersionInfo(filePath);
                if (info.ProductVersion != null && Version.TryParse(info.ProductVersion.Split('+')[0], out var v))
                {
                    return v;
                }
                if (info.FileVersion != null && Version.TryParse(info.FileVersion.Split('+')[0], out var v2))
                {
                    return v2;
                }
            }
            catch { }
            return new Version(0, 0, 0, 0);
        }
    }
}
