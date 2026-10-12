namespace Ultron.PortableInspection;

// One session owns this admission budget; failed or changed reads never release reservations.
internal sealed class SourceByteBudget
{
    private const ulong MaximumBytes = 256UL * 1024 * 1024;
    private ulong _reserved;

    internal bool TryReserve(ulong bytes)
    {
        if (bytes > MaximumBytes - _reserved) return false;
        _reserved += bytes;
        return true;
    }
}
