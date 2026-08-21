using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Safety
{
    /// <summary>
    /// Windows işletim sistemi çekirdek dosyalarını, sistem kayıtlarını, sürücülerini ve
    /// antivirüsün kendi dosyalarını kazara silinme veya karantinaya alınmaya karşı koruyan muhafız arayüzü.
    /// </summary>
    public interface IProtectedPathGuard
    {
        /// <summary>
        /// Verilen yolun korunan bir Windows veya AegisPC yolu olup olmadığını belirler.
        /// </summary>
        bool IsProtected(string path);

        /// <summary>
        /// Verilen yolun işletim sisteminin çökmesine neden olabilecek kritik çekirdek dosyası olup olmadığını belirler.
        /// </summary>
        bool IsCriticalSystemCore(string path);

        /// <summary>
        /// Yolun derin koruma ve kategori analizini gerçekleştirir.
        /// </summary>
        ProtectedPathEvaluation Evaluate(string path);
    }
}
