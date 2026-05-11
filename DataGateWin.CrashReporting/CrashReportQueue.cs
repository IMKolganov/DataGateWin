using System.Text.Json;

namespace DataGateWin.CrashReporting;

public sealed class CrashReportQueue
{
    readonly string _directory;

    public CrashReportQueue(string? queueDirectory = null)
    {
        _directory = queueDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DataGateWin",
            "crash-queue");

        Directory.CreateDirectory(_directory);
    }

    public string QueueDirectory => _directory;

    /// <summary>Persist a payload for retry. Thread-safe.</summary>
    public void Enqueue(string crashFilename, string payloadUtf8, string? processName = null)
    {
        var id = $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid():N}";
        var path = Path.Combine(_directory, $"{id}.queued.json");
        var dto = new QueuedDto(crashFilename, payloadUtf8, processName);
        var json = JsonSerializer.Serialize(dto);
        File.WriteAllText(path, json);
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
