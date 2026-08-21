using System.Data.Common;
using System.Threading;
using System.Threading.Tasks;

namespace AegisPC.Contracts.Services;

public interface IDatabaseService
{
    Task InitializeAsync(CancellationToken cancellationToken = default);
    string GetConnectionString();
    DbConnection CreateConnection();
}
