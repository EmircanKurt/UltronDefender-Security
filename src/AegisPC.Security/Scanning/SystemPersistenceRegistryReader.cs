using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32;

namespace AegisPC.Security.Scanning;

internal static class SystemPersistenceRegistryReader
{
    internal static List<SystemPersistenceObservation> Read(CancellationToken cancellationToken)
    {
        var observations = new List<SystemPersistenceObservation>();
        ReadDebuggerRedirects(observations, cancellationToken);
        ReadLogonConfiguration(observations);
        ReadGlobalLibraries(observations);
        ReadAutoruns(observations, cancellationToken);
        ReadServiceLibraries(observations, cancellationToken);
        return observations;
    }

    internal static void ReadAutoruns(List<SystemPersistenceObservation> observations, CancellationToken cancellationToken)
    {
        var sources = new[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
            (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
            (Registry.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM")
        };
        foreach (var (hive, path, label) in sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TryRead(observations, label + "\\" + path, () =>
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key == null) return;
                foreach (string name in key.GetValueNames())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Add(observations, SystemPersistenceObservationKind.Autorun, label + "\\" + path + "\\" + name,
                        name, key.GetValue(name)?.ToString());
                }
            });
        }
    }

    private static void ReadDebuggerRedirects(List<SystemPersistenceObservation> observations, CancellationToken cancellationToken)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        TryRead(observations, "HKLM\\" + path, () =>
        {
            using var root = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (root == null) return;
            foreach (string name in root.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var key = root.OpenSubKey(name, writable: false);
                Add(observations, SystemPersistenceObservationKind.DebuggerRedirect, "HKLM\\" + path + "\\" + name + "\\Debugger",
                    name, key?.GetValue("Debugger")?.ToString());
            }
        });
    }

    private static void ReadLogonConfiguration(List<SystemPersistenceObservation> observations)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        TryRead(observations, "HKLM\\" + path, () =>
        {
            using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (key == null) return;
            Add(observations, SystemPersistenceObservationKind.DesktopShell, "HKLM\\" + path + "\\Shell",
                "Winlogon Shell", key.GetValue("Shell")?.ToString());
            Add(observations, SystemPersistenceObservationKind.LogonInitializer, "HKLM\\" + path + "\\Userinit",
                "Winlogon Userinit", key.GetValue("Userinit")?.ToString());
        });
    }

    private static void ReadGlobalLibraries(List<SystemPersistenceObservation> observations)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        TryRead(observations, "HKLM\\" + path, () =>
        {
            using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (key == null) return;
            Add(observations, SystemPersistenceObservationKind.GlobalLibraryLoad, "HKLM\\" + path + "\\AppInit_DLLs",
                "AppInit_DLLs", key.GetValue("AppInit_DLLs")?.ToString());
        });
    }

    private static void ReadServiceLibraries(List<SystemPersistenceObservation> observations, CancellationToken cancellationToken)
    {
        const string path = @"SYSTEM\CurrentControlSet\Services";
        TryRead(observations, "HKLM\\" + path, () =>
        {
            using var root = Registry.LocalMachine.OpenSubKey(path, writable: false);
            if (root == null) return;
            foreach (string name in root.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var key = root.OpenSubKey(name + "\\Parameters", writable: false);
                Add(observations, SystemPersistenceObservationKind.ServiceLibrary, "HKLM\\" + path + "\\" + name + "\\Parameters\\ServiceDll",
                    name, key?.GetValue("ServiceDll")?.ToString());
            }
        });
    }

    private static void TryRead(List<SystemPersistenceObservation> observations, string source, Action reader)
    {
        try { reader(); }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            Trace.TraceWarning("Persistence configuration could not be read: {0}: {1}", source, ex.Message);
            Add(observations, SystemPersistenceObservationKind.CoverageGap, source, "Registry coverage", ex.Message);
        }
    }

    private static void Add(List<SystemPersistenceObservation> observations, SystemPersistenceObservationKind kind,
        string path, string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        observations.Add(new SystemPersistenceObservation { Kind = kind, ObjectPath = path, ObjectName = name, Value = value });
    }
}
