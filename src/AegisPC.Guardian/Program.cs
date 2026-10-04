using AegisPC.Contracts.Protection;
using AegisPC.Security.UltronAI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

// Deliberately not installed by current packaging. No vault writer, native kills, restarts or unauthenticated action endpoint.
if (!args.Contains("--guardian-pilot", StringComparer.Ordinal))
{
    Console.Error.WriteLine("Guardian pilot is not enabled. Authenticated IPC, exclusive vault migration and Windows VM gates are required.");
    return 2;
}
// The opt-in marker is not a key/value hosting argument.
var builder = Host.CreateApplicationBuilder(args.Where(arg => arg != "--guardian-pilot").ToArray());
builder.Services.AddWindowsService(options => options.ServiceName = "Ultron Guardian Pilot");
builder.Services.AddSingleton<IUltronDecisionEngine, UltronDecisionEngine>();
builder.Services.AddSingleton<IGuardianHealthMonitor, GuardianHealthMonitor>();
builder.Services.AddSingleton<PilotGatedActionAdapter>();
builder.Services.AddSingleton<IProtectionActionValidator>(sp => sp.GetRequiredService<PilotGatedActionAdapter>());
builder.Services.AddSingleton<IProtectionActionExecutor>(sp => sp.GetRequiredService<PilotGatedActionAdapter>());
builder.Services.AddSingleton<IProtectionActionBroker, ProtectionActionBroker>();
builder.Services.AddHostedService<GuardianPilotWorker>();
await builder.Build().RunAsync();
return 0;
