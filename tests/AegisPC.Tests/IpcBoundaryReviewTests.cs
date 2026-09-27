using System.Reflection;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using AegisPC.Infrastructure.Ipc;
using AegisPC.ServiceContracts.IpcMessages;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO.Pipes;
using AegisPC.App.Services;
using Xunit;

namespace AegisPC.Tests;

/// <summary>Benign protocol tests; no installed service or machine settings are changed.</summary>
public sealed class IpcBoundaryReviewTests
{
    [Fact]
    public async Task DisconnectedClient_DoesNotReportCachedProtectionOrAssumeAmsi()
    {
        using var client = new ServiceIpcClient();
        typeof(ServiceIpcClient).GetField("_lastKnownStatus", BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(client, new ProtectionStatus { ProtectionLevel = "fixture", IsServiceRunning = true,
                IsRealTimeEnabled = true, IsAmsiEnabled = true });
        var status = await client.GetStatusAsync();
        Assert.False(status.IsServiceRunning);
        Assert.False(status.IsRealTimeEnabled);
        Assert.False(status.IsAmsiEnabled);
    }

    [Fact]
    public async Task LocalListener_WithNoRegisteredService_IsNotTrusted()
    {
        var pipeName = "ReviewFixture_" + Guid.NewGuid().ToString("N");
        using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var accept = server.WaitForConnectionAsync(deadline.Token);
        await client.ConnectAsync(deadline.Token);
        await accept;
        Assert.False(PipeServiceIdentity.IsExpectedService(client, "ReviewNonexistent_" + Guid.NewGuid().ToString("N")));
    }
    [Theory]
    [InlineData("{}")]
    [InlineData("{\"Payload\":\"fixture\"}")]
    [InlineData("{\"CommandType\":999}")]
    [InlineData("{\"CommandType\":4,\"CommandType\":0}")]
    [InlineData("{\"CommandType\":\"StartScan\"}")]
    public void InvalidCommandEnvelope_IsNeverDefaultedToStartScan(string json)
    {
        Assert.False(ServiceCommandParser.TryParse(json, out var command));
        Assert.Null(command);
    }

    [Fact]
    public void ExistingClientCommand_StillParses()
    {
        Assert.True(ServiceCommandParser.TryParse("{\"CommandType\":4,\"Payload\":null}", out var command));
        Assert.Equal(ServiceCommandType.GetStatus, command!.CommandType);
    }

    [Fact]
    public async Task InputFrame_BoundsApplyBeforeNewlineAndParsing()
    {
        using var reader = new StringReader(new string('x', 33) + "\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => BoundedPipeProtocol.ReadCommandAsync(reader, default, 32));
    }

    [Fact]
    public async Task InputFrame_AtExactLimitAndBackToBackFrames_ArePreserved()
    {
        using var reader = new StringReader("1234\nnext\r\n");
        Assert.Equal("1234", await BoundedPipeProtocol.ReadCommandAsync(reader, default, 5));
        Assert.Equal("next", await BoundedPipeProtocol.ReadCommandAsync(reader, default, 5));
        Assert.Null(await BoundedPipeProtocol.ReadCommandAsync(reader, default, 5));
    }

    [Fact]
    public async Task IncompleteFrame_IsNotAcceptedAtDisconnect()
    {
        using var reader = new StringReader("{\"CommandType\":0}");
        await Assert.ThrowsAsync<InvalidDataException>(() => BoundedPipeProtocol.ReadCommandAsync(reader, default));
    }

    [Fact]
    public void LocalPipeAcl_RejectsNetworkAndDoesNotGrantInstanceCreationToUsers()
    {
        var rules = BoundedPipeProtocol.CreateLocalSecurity().GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<PipeAccessRule>().ToArray();
        Assert.Contains(rules, rule => rule.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.NetworkSid, null)) &&
            rule.AccessControlType == AccessControlType.Deny);
        var users = Assert.Single(rules.Where(rule => rule.IdentityReference.Equals(
            new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null))));
        Assert.Equal((PipeAccessRights)0, users.PipeAccessRights & PipeAccessRights.CreateNewInstance);
    }
    [Fact]
    public void InvalidSignature_DoesNotReserveLegitimateNonce()
    {
        using var server = new SecureNamedPipeServer("ReviewOnly_" + Guid.NewGuid().ToString("N"), "temporary fixture secret");
        var message = CreateSignedMessage();
        var signature = message.SignatureHmac;
        message.SignatureHmac = Convert.ToBase64String(new byte[32]);
        Assert.False(Validate(server, message));
        message.SignatureHmac = signature;
        Assert.True(Validate(server, message));
        Assert.False(Validate(server, message));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(long.MaxValue)]
    public void OutOfRangeTimestamp_IsRejectedWithoutException(long ticks)
    {
        using var server = new SecureNamedPipeServer("ReviewOnly_" + Guid.NewGuid().ToString("N"), "temporary fixture secret");
        var message = CreateSignedMessage();
        message.TimestampUtcTicks = ticks;
        Assert.False(Validate(server, message));
    }

    [Fact]
    public void DelimiterInCommand_CannotReuseSignatureForAnotherCommand()
    {
        using var server = new SecureNamedPipeServer("ReviewOnly_" + Guid.NewGuid().ToString("N"), "temporary fixture secret");
        var message = CreateSignedMessage("GetStatus|metadata", "value");
        Assert.False(Validate(server, message));
    }

    [Fact]
    public void OversizedPayload_IsRejectedEvenWithValidSignature()
    {
        using var server = new SecureNamedPipeServer("ReviewOnly_" + Guid.NewGuid().ToString("N"), "temporary fixture secret");
        Assert.False(Validate(server, CreateSignedMessage(payload: new string('x', 65_537))));
    }

    private static IpcSecureMessage CreateSignedMessage(string command = "GetStatus", string payload = "fixture")
    {
        var message = new IpcSecureMessage { Command = command, Payload = payload };
        using var hmac = new HMACSHA256(SHA256.HashData(Encoding.UTF8.GetBytes("temporary fixture secret")));
        message.SignatureHmac = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(
            $"{message.Command}|{message.Payload}|{message.TimestampUtcTicks}|{message.Nonce}")));
        return message;
    }

    private static bool Validate(SecureNamedPipeServer server, IpcSecureMessage message)
    {
        var method = typeof(SecureNamedPipeServer).GetMethod("ValidateMessage", BindingFlags.NonPublic | BindingFlags.Instance)!;
        return (bool)method.Invoke(server, new object[] { message })!;
    }
}
