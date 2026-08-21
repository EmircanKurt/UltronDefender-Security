using System;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services
{
    public interface IWindowsToastNotificationService
    {
        void ShowToast(string title, string message, string type = "Info");
    }

    public interface INotificationAggregator
    {
        TimeSpan AggregationWindow { get; set; }
        void PushThreatEvent(string threatName, string objectPath, string actionTaken, bool isCritical = false);
        void Flush();
    }
}
