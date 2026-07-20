# Capture d'écran de l'appli via Edge headless + Chrome DevTools Protocol.
# (--screenshot natif shoote au load, avant que la WebSocket n'alimente les
# graphes ; ici on attend réellement puis on déclenche la capture via CDP.)
param(
    [string]$Url = "http://localhost:8080/",
    [string]$Out = "docs\screenshot.png",
    [int]$WaitSec = 20,
    [int]$DebugPort = 9333,
    [int]$Width = 1720,
    [int]$Height = 1000
)

$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edge)) { $edge = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
$profileDir = Join-Path $env:TEMP "netman-shot-profile"

$proc = Start-Process -FilePath $edge -PassThru -ArgumentList @(
    "--headless=new", "--disable-gpu", "--no-first-run",
    "--user-data-dir=`"$profileDir`"",
    "--remote-debugging-port=$DebugPort",
    "--window-size=$Width,$Height",
    "`"$Url`""
)
try {
    Start-Sleep $WaitSec

    $targets = Invoke-RestMethod "http://localhost:$DebugPort/json"
    $page = $targets | Where-Object { $_.type -eq "page" -and $_.url -like "*$([Uri]::new($Url).Authority)*" } | Select-Object -First 1
    if (-not $page) { throw "page target not found" }

    $ws = [System.Net.WebSockets.ClientWebSocket]::new()
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(30))
    $ws.ConnectAsync([Uri]$page.webSocketDebuggerUrl, $cts.Token).Wait()

    $cmd = '{"id":1,"method":"Page.captureScreenshot","params":{"format":"png"}}'
    $bytes = [Text.Encoding]::UTF8.GetBytes($cmd)
    $ws.SendAsync([ArraySegment[byte]]::new($bytes), 'Text', $true, $cts.Token).Wait()

    $buffer = [byte[]]::new(1MB)
    $sb = [Text.StringBuilder]::new()
    do {
        $seg = [ArraySegment[byte]]::new($buffer)
        $result = $ws.ReceiveAsync($seg, $cts.Token).GetAwaiter().GetResult()
        [void]$sb.Append([Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count))
    } while (-not $result.EndOfMessage)
    $ws.Dispose()

    $reply = $sb.ToString() | ConvertFrom-Json
    if (-not $reply.result.data) { throw "no screenshot data: $($sb.ToString().Substring(0, 200))" }
    [IO.File]::WriteAllBytes((Resolve-Path (Split-Path $Out) | Join-Path -ChildPath (Split-Path $Out -Leaf)), [Convert]::FromBase64String($reply.result.data))
    Write-Host "written: $Out"
} finally {
    if (-not $proc.HasExited) { $proc.Kill() }
    Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue
}
