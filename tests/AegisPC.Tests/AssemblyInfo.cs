using Xunit;

// Disable parallel test execution across all classes in AegisPC.Tests
// Prevents race conditions during disk I/O, FileSystemWatcher events, and Temp folder tests.
[assembly: CollectionBehavior(CollectionBehavior.CollectionPerAssembly, DisableTestParallelization = true, MaxParallelThreads = 1)]
