using AegisPC.Contracts.Detection;

namespace AegisPC.Security.Scanning;

public partial class ArchiveSafetyScanner
{
    private static void AppendMemberEvidence(ArchiveScanResult result, List<SecurityEvidence> evidence, string memberName, string sha256)
    {
        int capacity = Math.Max(0, 512 - result.MemberEvidences.Count);
        foreach (var item in evidence.Take(capacity))
        {
            item.Metadata["ArchiveMember"] = memberName;
            item.Metadata["ArchiveMemberSHA256"] = sha256;
            result.MemberEvidences.Add(item);
        }
        if (evidence.Count > capacity)
        {
            result.RecordCoverageGap("Arşiv üyesi kanıt çıktı bütçesi aşıldı; kalan kapsam incelenemedi.");
        }
    }
}
