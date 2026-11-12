namespace Infrastructure.BackgroundJobs;

using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public sealed class RevokedTokenCleanupService(
    IServiceScopeFactory scopeFactory, // <--- 1. Inject scope factory instead of AppDbContext directly
    ILogger<RevokedTokenCleanupService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            // <--- 2. Create a temporary scope on each tick to safely resolve the Scoped DbContext
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var deleted = await db.RevokedTokens
                .Where(t => t.ExpiresAtUtc < DateTime.UtcNow)
                .ExecuteDeleteAsync(stoppingToken);

            if (deleted > 0)
            {
                logger.LogInformation("Cleaned up {Count} expired revoked tokens.", deleted);
            }
        }
    }
}