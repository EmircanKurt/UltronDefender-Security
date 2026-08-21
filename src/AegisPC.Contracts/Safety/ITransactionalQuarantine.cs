using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Atomik, adımlı ve geri alınabilir (Transactional Rollback) Güvenli Karantina Motoru Arayüzü.
    /// </summary>
    public interface ITransactionalQuarantine
    {
        /// <summary>
        /// Dosyayı atomik işlem aşamalarıyla karantinaya alır. Herhangi bir aşamada hata olursa orijinal dosya bozulmadan işlem geri alınır.
        /// </summary>
        Task<QuarantineTransactionResult> ExecuteQuarantineAsync(QuarantineRequest request, CancellationToken cancellationToken = default);

        /// <summary>
        /// Karantinaya alınmış dosyayı şifresini çözerek güvenle orijinal veya özel bir konuma geri yükler.
        /// </summary>
        Task<QuarantineRestoreResult> ExecuteRestoreAsync(int quarantineId, string? targetOverride = null, CancellationToken cancellationToken = default);
    }
}
