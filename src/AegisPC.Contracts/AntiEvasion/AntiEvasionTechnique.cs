using System;

namespace AegisPC.Contracts.AntiEvasion
{
    [Flags]
    public enum AntiEvasionTechnique
    {
        None = 0,
        AntiDebugging = 1 << 0,
        AntiVmHypervisor = 1 << 1,
        TimingSleepDelay = 1 << 2,
        IndirectSyscallStubs = 1 << 3,
        AmsiEtwPatching = 1 << 4,
        EnvironmentalKeying = 1 << 5,
        UnbackedExecutableMemory = 1 << 6
    }
}
