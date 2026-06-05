param(
    [switch]$clean,
    [switch]$force,
    [switch]$kill,
    [string]$src = "C:\Windows\System32",
    [string]$out = "$PSScriptRoot\BinsDB"
)

# please make sure you IDA in your PATH!
$cfg = @{
    dbghelp_path = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbghelp.dll"
    symbol_path  = "srv*c:\symbols*http://msdl.microsoft.com/download/symbols"
    src          = $src
    db_dir       = $out
    max_jobs     = 10
    exts         = @(".dll", ".exe", ".sys", ".efi")
    exclude_dirs = @()
}

if ($kill) {
    $pidfile = Join-Path $out ".runner.pid"
    if (Test-Path $pidfile) {
        $rpid = (Get-Content $pidfile).Trim()
        Write-Host "[kill] killing process tree $rpid..."
        & taskkill /T /F /PID $rpid 2>$null
        Remove-Item $pidfile -Force -EA SilentlyContinue
    }
    Write-Host "[kill] killing straggler IDA processes..."
    @('ida', 'ida64', 'idat', 'idat64') | ForEach-Object {
        Stop-Process -Name $_ -Force -EA SilentlyContinue
    }
    if (Test-Path $out) {
        Get-ChildItem "$out\*\*\.processing" -EA SilentlyContinue | Remove-Item -Force
    }
    Write-Host "[kill] done"
    exit 0
}

function get_hash([string]$path, [int]$len = 8) {
    (Get-FileHash $path -Algorithm SHA256).Hash.Substring(0, $len).ToLower()
}

function rm_db([string]$db_dir, [bool]$force_rm) {
    if (-not (Test-Path $db_dir)) {
        Write-Output "db dir doesn't exist"
        return
    }
    if (-not $force_rm) {
        $cnt = (Get-ChildItem $db_dir -Directory -EA SilentlyContinue).Count
        $ans = Read-Host "delete $cnt dirs in $db_dir? (y/N)"
        if ($ans -ne 'y') { Write-Output "abort"; exit 0 }
    }
    Write-Output "removing db..."
    Remove-Item $db_dir -Recurse -Force -EA SilentlyContinue
}

function get_bins([string]$path, [string[]]$exts, [string[]]$exclude) {
    $files = Get-ChildItem $path -Recurse -File -EA SilentlyContinue |
        Where-Object { $_.Extension -in $exts }
    if ($exclude.Count -gt 0) {
        $pat = "\\(" + ($exclude -join "|") + ")\\"
        $files = $files | Where-Object { $_.FullName -notmatch $pat }
    }
    $files | Select-Object -ExpandProperty FullName
}

function copy_to_db([string[]]$files, [string]$db_dir) {
    $stats = @{ copied = 0; skipped = 0 }
    $paths = [Collections.ArrayList]::new()
    
    foreach ($src in $files) {
        $name = [IO.Path]::GetFileNameWithoutExtension($src)
        $fname = [IO.Path]::GetFileName($src)
        $hash = get_hash $src
        
        $dest_dir = Join-Path $db_dir $name | Join-Path -ChildPath $hash
        $dest = Join-Path $dest_dir $fname
        
        if (Test-Path $dest) {
            $stats.skipped++
        } else {
            Write-Output "[+] $fname -> $name/$hash/"
            New-Item -ItemType Directory -Path $dest_dir -Force -EA SilentlyContinue | Out-Null
            Copy-Item $src $dest -Force -EA SilentlyContinue
            $src | Out-File (Join-Path $dest_dir ".source") -Encoding UTF8 -Force
            $stats.copied++
        }
        [void]$paths.Add($dest)
    }
    @{ paths = $paths; stats = $stats }
}

function get_pending([string[]]$paths) {
    $pending = [Collections.ArrayList]::new()
    foreach ($p in $paths) {
        $dir = [IO.Path]::GetDirectoryName($p)
        if (-not (Test-Path (Join-Path $dir ".complete")) -and -not (Test-Path (Join-Path $dir ".processing"))) {
            [void]$pending.Add($p)
        }
    }
    $pending
}

function split_arr([array]$arr, [int]$parts) {
    if ($arr.Count -eq 0) { return @() }
    $sz = [Math]::Ceiling($arr.Count / $parts)
    $chunks = [Collections.ArrayList]::new()
    for ($i = 0; $i -lt $arr.Count; $i += $sz) {
        $chunk = [Collections.ArrayList]::new()
        $end = [Math]::Min($i + $sz, $arr.Count)
        for ($j = $i; $j -lt $end; $j++) { [void]$chunk.Add($arr[$j]) }
        [void]$chunks.Add($chunk.ToArray())
    }
    $chunks.ToArray()
}

$job_script = {
    param([array]$bins, [string]$root, [int]$id, [string]$db_dir)
    
    if ($env:Path -notlike "*$root\IDA*") { $env:Path += ";$root\IDA" }
    $script_name = "analyze.py"
    $script_path = Join-Path $root $script_name
    if ($script_path.Contains(' ')) {
        $safe_dir = Join-Path $env:TEMP "ida_reach_scripts"
        New-Item -ItemType Directory -Path $safe_dir -Force -EA SilentlyContinue | Out-Null
        Copy-Item $script_path (Join-Path $safe_dir $script_name) -Force
        $script_path = Join-Path $safe_dir $script_name
    }
    $cnt = 0
    
    foreach ($bin in $bins) {
        $dir = [IO.Path]::GetDirectoryName($bin)
        $name = [IO.Path]::GetFileName($bin)
        $complete = Join-Path $dir ".complete"
        $processing = Join-Path $dir ".processing"
        
        if (Test-Path $complete) {
            Write-Output "[J$id] skip: $name"
            continue
        }
        
        try { New-Item $processing -ItemType File -EA Stop | Out-Null }
        catch { Write-Output "[J$id] locked: $name"; continue }
        
        Write-Output "[J$id] start: $name"
        New-Item -ItemType Directory -Path $dir -Force -EA SilentlyContinue | Out-Null
        New-Item (Join-Path $dir "analysis_results.idaout") -ItemType File -Force | Out-Null
        
        # you need to have ida in your PATH!
        [Diagnostics.Process]::Start("ida.exe", "-c -A -S`"$script_path`" `"$bin`"").WaitForExit(10000000) | Out-Null
        
        Remove-Item $processing -EA SilentlyContinue
        New-Item $complete -ItemType File -Force | Out-Null
        
        $result = Get-Content (Join-Path $dir "analysis_results.idaout") -EA SilentlyContinue
        $status = if ($result) { "done" } else { "ERR" }
        Write-Output "[J${id}] ${status}: $name"
        $cnt++
    }
    "[J$id] processed $cnt"
}

if ($clean) {
    rm_db $cfg.db_dir $force
    exit 0
}

Write-Output "searching $($cfg.src)..."
$bins = @(get_bins $cfg.src $cfg.exts $cfg.exclude_dirs)
Write-Output "found $($bins.Count) binaries"

Write-Output "sync with db..."
New-Item -ItemType Directory -Path $cfg.db_dir -Force -EA SilentlyContinue | Out-Null
$db = copy_to_db $bins $cfg.db_dir
Write-Output "copied: $($db.stats.copied), skipped: $($db.stats.skipped)"

$pending = @(get_pending $db.paths)
$total = $db.paths.Count

if ($pending.Count -eq 0) {
    Write-Output "all $total done"
    exit 0
}

Write-Output "pending: $($pending.Count) / $total"

$chunks = split_arr $pending $cfg.max_jobs
Write-Output "starting $($chunks.Count) jobs..."

$pidfile = Join-Path $cfg.db_dir ".runner.pid"
$PID | Set-Content $pidfile -Force

$jobs = @()
for ($i = 0; $i -lt $chunks.Count; $i++) {
    Write-Output "[+] job ${i}: $($chunks[$i].Count) bins\n"
    $jobs += Start-Job -ScriptBlock $job_script -ArgumentList $chunks[$i], $PSScriptRoot, $i, $cfg.db_dir
}

function stop_all {
    Write-Host "`n[cleanup] stopping everything..."
    $jobs | Stop-Job -EA SilentlyContinue
    $jobs | Remove-Job -Force -EA SilentlyContinue
    @('ida', 'ida64', 'idat', 'idat64') | ForEach-Object {
        Stop-Process -Name $_ -Force -EA SilentlyContinue
    }
    Get-ChildItem "$($cfg.db_dir)\*\*\.processing" -EA SilentlyContinue | Remove-Item -Force
    Remove-Item $pidfile -Force -EA SilentlyContinue
    Write-Host "[cleanup] done"
}

# intercept ctrl+c so we can clean up instead of orphaning everything
[Console]::TreatControlCAsInput = $true

try {
    while (Get-Job -State Running) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if ($key.Key -eq 'C' -and ($key.Modifiers -band [ConsoleModifiers]::Control)) {
                stop_all
                exit 1
            }
        }
        $done = (Get-ChildItem "$($cfg.db_dir)\*\*\.complete" -EA SilentlyContinue).Count
        $active = (Get-ChildItem "$($cfg.db_dir)\*\*\.processing" -EA SilentlyContinue).Count
        Write-Host "`r[progress] done: $done/$total | active: $active    " -NoNewline
        $jobs | Receive-Job
        Start-Sleep -Seconds 1
    }
} finally {
    [Console]::TreatControlCAsInput = $false
    Remove-Item $pidfile -Force -EA SilentlyContinue
}

Write-Host ""
$jobs | ForEach-Object {
    Write-Output "`njob $($_.Id):"
    Receive-Job $_
    Remove-Job $_
}

$final = (Get-ChildItem "$($cfg.db_dir)\*\*\.complete" -EA SilentlyContinue).Count
Write-Output "complete: $final / $total"