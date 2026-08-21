using System;
using System.IO;

namespace AegisPC.Core.Constants;

public static class KnownPaths
{
    public static string System32 => Environment.GetFolderPath(Environment.SpecialFolder.System);
    public static string WindowsDir => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    public static string ProgramFiles => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    public static string ProgramFilesX86 => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    public static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    public static string Temp => Path.GetTempPath();
    public static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    public static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    public static string Downloads => Path.Combine(UserProfile, "Downloads");
    public static string CommonStartup => Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
    public static string UserStartup => Environment.GetFolderPath(Environment.SpecialFolder.Startup);
}
