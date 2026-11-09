using System.Text.Json;

namespace DataGateWin.CrashReporting;

public sealed class CrashReportQueue
{
    readonly string _directory;
    readonly long _maxDirectoryBytes;

    public CrashReportQueue(string? queueDirectory = null, long maxDirectoryBytes = InMemoryLogBudget.MaxQueueBytes)
    {
        _directory = queueDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DataGateWin",
            "crash-queue");
        _maxDirectoryBytes = maxDirectoryBytes > 0 ? maxDirectoryBytes : InMemoryLogBudget.MaxQueueBytes;

        Directory.CreateDirectory(_directory);
    }

    public string QueueDirectory => _directory;

    /// <summary>Persist a payload for retry. Thread-safe. Drops oldest files when over budget.</summary>
    public void Enqueue(string crashFilename, string payloadUtf8, string? processName = null)
    {
        var id = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid():N}";
        var path = Path.Combine(_directory, $"{id}.queued.json");
        var dto = new QueuedDto(crashFilename, payloadUtf8, processName);
        var json = JsonSerializer.Serialize(dto);
        File.WriteAllText(path, json);
        TrimDirectoryToBudget();
    }

    public IReadOnlyList<QueuedCrashReport> ReadPending()
    {
        if (!Directory.Exists(_directory))
            return Array.Empty<QueuedCrashReport>();

        var list = new List<QueuedCrashReport>();
        foreach (var path in Directory.EnumerateFiles(_directory, "*.queued.json"))
        {
            try
            {
                var json = File.ReadAllText(path);
                var dto = JsonSerializer.Deserialize<QueuedDto>(json);
                if (dto?.Filename is null || dto.Payload is null)
                    continue;

                list.Add(new QueuedCrashReport(Path.GetFileName(path)!, path, dto.Filename, dto.Payload, dto.ProcessName));
            }
            catch
            {
                // Skip corrupted entries
            }
        }

        return list;
    }

    public bool TryRemove(string absolutePath)
    {
        try
        {
            if (File.Exists(absolutePath))
            {
                File.Delete(absolutePath);
                return true;
            }
        }
        catch
        {
            // ignored
        }

        return false;
    }

    /// <summary>Delete oldest queue files until total size is within budget.</summary>
    public void TrimDirectoryToBudget()
    {
        if (!Directory.Exists(_directory))
            return;

        FileInfo[] files;
        try
        {
            files = new DirectoryInfo(_directory)
                .EnumerateFiles("*.queued.json")
                .OrderBy(f => f.CreationTimeUtc)
                .ThenBy(f => f.Name, StringComparer.Ordinal)
                .ToArray();
        }
        catch
        {
            return;
        }

        long total = 0;
        foreach (var f in files)
            total += f.Length;

        foreach (var f in files)
        {
            if (total <= _maxDirectoryBytes)
                break;

            try
            {
                total -= f.Length;
                f.Delete();
            }
            catch
            {
                // best-effort
            }
        }
    }

    sealed class QueuedDto
    {
        public string Filename { get; set; } = "";
        public string Payload { get; set; } = "";
        public string? ProcessName { get; set; }

        public QueuedDto()
        {
        }

        public QueuedDto(string filename, string payload, string? processName)
        {
            Filename = filename;
            Payload = payload;
            ProcessName = processName;
        }
    }
}

public sealed record QueuedCrashReport(
    string QueueFileName,
    string AbsolutePath,
    string CrashFilename,
    string Payload,
    string? ProcessName);
