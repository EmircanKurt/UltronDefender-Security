#pragma once

// The legacy path/PID/boolean ABI cannot authorize an identity-bound native action.
// A successful transport exchange is not a receipt that an action was applied.
static BOOLEAN AegisIsValidLegacyReply(NTSTATUS status, ULONG replyBytes, BOOLEAN blockByte)
{
    return status == STATUS_SUCCESS && replyBytes == sizeof(BOOLEAN) &&
        (blockByte == FALSE || blockByte == TRUE);
}
