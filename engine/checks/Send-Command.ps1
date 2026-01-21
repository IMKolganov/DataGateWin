param(
  [Parameter(Mandatory=$true)][string]$SessionId,
  [Parameter(Mandatory=$true)][ValidateSet("GetStatus","StartSession","StopSession","StopEngine")][string]$Type,
  [string]$PayloadJson = "{}",
  [string]$Id = "1"
)

$controlPipeName = "datagate.engine.$SessionId.control"

function Write-LineJson([System.IO.StreamWriter]$writer, [string]$jsonLine) {
  $writer.WriteLine($jsonLine)
  $writer.Flush()
}

$client = New-Object System.IO.Pipes.NamedPipeClientStream(".", $controlPipeName, [System.IO.Pipes.PipeDirection]::InOut)
$client.Connect(5000)

$reader = New-Object System.IO.StreamReader($client, [System.Text.Encoding]::UTF8)
$writer = New-Object System.IO.StreamWriter($client, [System.Text.Encoding]::UTF8)
$writer.AutoFlush = $true

# Command JSON line (assumed by TryParseCommandLine)
$cmdLine = "{""id"":""$Id"",""type"":""$Type"",""payload"":$PayloadJson}"

Write-Host "Sending: $cmdLine"
Write-LineJson $writer $cmdLine

# Read one response line
$response = $reader.ReadLine()
Write-Host "Response: $response"
