param(
  [Parameter(Mandatory=$true)][string]$SessionId
)

$eventsPipe = "\\.\pipe\datagate.engine.$SessionId.events"

Write-Host "Connecting to events pipe: $eventsPipe"

$client = New-Object System.IO.Pipes.NamedPipeClientStream(".", "datagate.engine.$SessionId.events", [System.IO.Pipes.PipeDirection]::In)
$client.Connect(5000)

$reader = New-Object System.IO.StreamReader($client, [System.Text.Encoding]::UTF8)

Write-Host "Connected. Waiting for events..."
while ($true) {
  $line = $reader.ReadLine()
  if ($null -eq $line) { break }
  Write-Host $line
}

Write-Host "Events pipe closed."
