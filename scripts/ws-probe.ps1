# Client WebSocket minimal pour valider le jalon 3 :
# affiche les N premiers deltas JSON reçus sur ws://localhost:PORT/ws.
param(
    [int]$Port = 8080,
    [int]$Count = 20,
    [int]$TimeoutSec = 15
)

$ws = [System.Net.WebSockets.ClientWebSocket]::new()
$cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSec))
try {
    $ws.ConnectAsync([Uri]"ws://localhost:$Port/ws", $cts.Token).Wait()
    Write-Host "connected to ws://localhost:$Port/ws"
    $buffer = [byte[]]::new(65536)
    $received = 0
    while ($received -lt $Count -and $ws.State -eq 'Open') {
        $segment = [ArraySegment[byte]]::new($buffer)
        $message = ""
        do {
            $result = $ws.ReceiveAsync($segment, $cts.Token).GetAwaiter().GetResult()
            $message += [Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count)
        } while (-not $result.EndOfMessage)
        if ($result.MessageType -eq 'Close') { break }
        $received++
        Write-Host ("[{0,3}] {1}" -f $received, $message)
    }
    Write-Host "done: $received messages"
} finally {
    if ($ws.State -eq 'Open') {
        try { $ws.CloseAsync('NormalClosure', 'bye', [Threading.CancellationToken]::None).Wait(1000) | Out-Null } catch {}
    }
    $ws.Dispose()
}
