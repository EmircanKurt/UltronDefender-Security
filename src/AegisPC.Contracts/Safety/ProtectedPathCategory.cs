namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Korumalı sistem ve güvenlik yolu kategorileri.
    /// </summary>
    public enum ProtectedPathCategory
    {
        None = 0,
        WindowsKernelAndBoot = 1,
        WindowsSystem32Core = 2,
        WindowsDrivers = 3,
        WindowsRegistryHives = 4,
        WindowsComponentStoreWinSxS = 5,
        WindowsSystemVolumeInformation = 6,
        AegisSecuritySelfProtection = 7,
        ActiveQuarantineVault = 8
    }
}
