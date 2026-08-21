using System;

namespace AegisPC.Contracts.PE
{
    /// <summary>
    /// Microsoft PE Rich Header içinde yer alan derleyici/ürün kaydı.
    /// </summary>
    public class PeRichHeaderEntry
    {
        /// <summary>
        /// Derleyici / Araç Kimliği (Compiler ID)
        /// </summary>
        public ushort CompilerId { get; set; }

        /// <summary>
        /// Derleyici Yapı Numarası (Build Number)
        /// </summary>
        public ushort BuildNumber { get; set; }

        /// <summary>
        /// Ürün Kimliği (Product ID)
        /// </summary>
        public ushort ProductId { get; set; }

        /// <summary>
        /// Kullanım Sayısı (Object/Module Count)
        /// </summary>
        public uint Count { get; set; }

        /// <summary>
        /// İnsan tarafından okunabilir araç açıklaması (Örn: "Visual C++ 2019 v16.8 (C++)")
        /// </summary>
        public string Description { get; set; } = string.Empty;

        public override string ToString() => $"[Prod: {ProductId}, Build: {BuildNumber}, Count: {Count}] {Description}";
    }
}
