using System;
using System.Collections.Generic;
using System.IO;
using AegisPC.Core.Enums;
using AegisPC.Core.Models;

namespace AegisPC.Persistence.Startup
{
    public static class StartupFolderScanner
    {
        public static List<StartupItem> ScanStartupFolders()
        {
            var items = new List<StartupItem>();

            var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);

            ScanFolder(userStartup, "Kullanıcı Başlangıç Klasörü", items);
            ScanFolder(commonStartup, "Ortak Başlangıç Klasörü", items);

            return items;
        }

        private static void ScanFolder(string folderPath, string sourceLabel, List<StartupItem> items)
        {
            if (!Directory.Exists(folderPath)) return;

            try
            {
                var files = Directory.GetFiles(folderPath);
                foreach (var file in files)
                {
                    var fileInfo = new FileInfo(file);
                    items.Add(new StartupItem
                    {
                        Name = Path.GetFileNameWithoutExtension(fileInfo.Name),
                        FilePath = file,
                        Source = sourceLabel,
                        IsEnabled = true,
                        RiskLevel = RiskLevel.Clean,
                        ImpactLevel = ImpactLevel.Low
                    });
                }
            }
            catch { }
        }
    }
}
