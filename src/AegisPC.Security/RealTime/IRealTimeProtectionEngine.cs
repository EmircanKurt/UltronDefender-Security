using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using AegisPC.Core.Models;

namespace AegisPC.Security.RealTime
{
    /// <summary>
    /// Gerçek zamanlı dosya sistemi izleme, tehdit tespiti ve proaktif müdahale motorunun servis sözleşmesi.
    /// </summary>
    public interface IRealTimeProtectionEngine
    {
        /// <summary>
        /// Gerçek zamanlı koruma döngüsünü ve dosya izleyicilerini başlatır.
        /// </summary>
        void Start();

        /// <summary>
        /// Gerçek zamanlı koruma döngüsünü durdurur ve kaynakları askıya alır.
        /// </summary>
        void Stop();

        /// <summary>
        /// Gerçek zamanlı korumanın şu anda etkin olup olmadığını belirtir.
        /// </summary>
        bool IsRunning { get; }

        /// <summary>
        /// Gerçek zamanlı olarak izlenen klasör yollarının salt-okunur listesi.
        /// </summary>
        IReadOnlyList<string> WatchedLocations { get; }

        /// <summary>
        /// İzleme kapsamına yeni bir dizin yolu ekler.
        /// </summary>
        /// <param name="path">İzlenecek dizinin tam yolu.</param>
        void AddWatchDirectory(string path);

        /// <summary>
        /// Belirtilen dizin yolunu izleme kapsamından çıkarır.
        /// </summary>
        /// <param name="path">Kapsamdan çıkarılacak dizin yolu.</param>
        void RemoveWatchDirectory(string path);

        /// <summary>
        /// Bir güvenlik bulgusu veya tehdit tespit edildiğinde tetiklenen olay.
        /// </summary>
        event Action<SecurityFinding>? OnThreatDetected;

        /// <summary>
        /// Kritik seviyede bir güvenlik olayı (incident) oluştuğunda tetiklenen olay.
        /// </summary>
        event Action<SecurityIncident>? OnIncidentCreated;

        /// <summary>
        /// Kullanıcı arayüzüne bildirim (toast) gönderilmesi gerektiğinde tetiklenen olay.
        /// Parametreler: Başlık, Mesaj, Bildirim Türü (Success, Warning, Danger).
        /// </summary>
        event Action<string, string, string>? OnNotificationRaised;

        /// <summary>
        /// Gerçek zamanlı dosya eylemleri canlı olarak gerçekleştiğinde tetiklenen telemetri olayı.
        /// </summary>
        event Action<RealTimeActivityEvent>? OnActivityLogged;

        /// <summary>
        /// Gerçek zamanlı korumanın sağlık durumu değiştiğinde tetiklenen olay (Sağlıklı/Sağlıksız, Durum Mesajı).
        /// </summary>
        event Action<bool, string>? OnProtectionHealthChanged;

        /// <summary>
        /// Belirtilen tekil bir dosyayı derinlemesine heuristik, imza ve entropi analizinden geçirerek karara bağlar.
        /// </summary>
        /// <param name="filePath">İncelenecek dosyanın tam yolu.</param>
        /// <param name="cancellationToken">İptal belirteci.</param>
        /// <returns>Analiz kararını ve telemetri süresini içeren sonuç nesnesi.</returns>
        Task<RealTimeVerdictResult> InspectFileAsync(string filePath, CancellationToken cancellationToken = default);
    }
}
