namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// NTFS Reparse Point (Yeniden Ayrıştırma Noktası) türü.
    /// </summary>
    public enum ReparsePointType
    {
        None = 0,
        SymbolicLink = 1,
        MountPointOrJunction = 2,
        AppExecLink = 3,
        OtherReparsePoint = 4
    }
}
