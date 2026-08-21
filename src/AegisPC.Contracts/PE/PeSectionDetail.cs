using System;

namespace AegisPC.Contracts.PE
{
    /// <summary>
    /// PE Bölüm (Image Section) yapısal ve güvenlik öznitelikleri.
    /// </summary>
    public class PeSectionDetail
    {
        public string Name { get; set; } = string.Empty;
        public uint VirtualAddress { get; set; }
        public uint VirtualSize { get; set; }
        public uint RawAddress { get; set; }
        public uint RawSize { get; set; }
        public uint Characteristics { get; set; }

        /// <summary>
        /// Bölümün Shannon Entropisi (0.00 - 8.00). > 7.2 ise şifrelenmiş/paketlenmiş veri.
        /// </summary>
        public double Entropy { get; set; }

        /// <summary>
        /// IMAGE_SCN_MEM_EXECUTE (0x20000000)
        /// </summary>
        public bool IsExecutable { get; set; }

        /// <summary>
        /// IMAGE_SCN_MEM_WRITE (0x80000000)
        /// </summary>
        public bool IsWritable { get; set; }

        /// <summary>
        /// IMAGE_SCN_MEM_READ (0x40000000)
        /// </summary>
        public bool IsReadable { get; set; }

        /// <summary>
        /// W+X Anomalisi (Hem yazılabilir hem çalıştırılabilir - Self-modifying / JIT / Shellcode)
        /// </summary>
        public bool IsWritableAndExecutable => IsWritable && IsExecutable;

        /// <summary>
        /// Bilinen şüpheli/packer bölüm ismi (UPX, Themida, VMProtect, Aspack vb.)
        /// </summary>
        public bool IsKnownPackerName { get; set; }

        public override string ToString() => $"Section: {Name} (VSize: {VirtualSize}, RSize: {RawSize}, Entropy: {Entropy:F2}, W+X: {IsWritableAndExecutable})";
    }
}
