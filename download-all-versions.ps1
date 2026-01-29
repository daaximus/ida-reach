param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$file,
    
    [Parameter(Position=1)]
    [string]$out_dir = ".",
    
    [switch]$skip_pdb,
    
    [ValidateSet("all", "x64", "x86", "arm64")]
    [string]$arch = "all"
)

$ErrorActionPreference = "Stop"

function get_arch([int]$machine_type) {
    switch ($machine_type) {
        0x8664 { return "x64" }
        0xAA64 { return "arm64" }
        0x14C  { return "x86" }
        default { return "unknown" }
    }
}

function get_pdb_info([string]$pe_path) {
    try {
        $fs = [IO.File]::OpenRead($pe_path)
        $br = New-Object IO.BinaryReader($fs)

        $fs.Position = 0x3C
        $pe_offset = $br.ReadInt32()
        $fs.Position = $pe_offset
        $pe_sig = $br.ReadUInt32()

        if ($pe_sig -ne 0x4550) { $br.Close(); $fs.Close(); return $null }

        $machine = $br.ReadUInt16()
        $num_sections = $br.ReadUInt16()

        $fs.Position += 12
        $opt_hdr_size = $br.ReadUInt16()
        $fs.Position += 2

        $opt_start = $fs.Position
        $magic = $br.ReadUInt16()
        $is_pe32plus = ($magic -eq 0x20B)
        
        $data_dir_base = if ($is_pe32plus) { 112 } else { 96 }
        $debug_dir_offset = $data_dir_base + 48
        $fs.Position = $opt_start + $debug_dir_offset
        
        $debug_rva = $br.ReadUInt32()
        $debug_size = $br.ReadUInt32()
        
        if ($debug_rva -eq 0) { $br.Close(); $fs.Close(); return $null }
        
        $fs.Position = $opt_start + $opt_hdr_size
        $debug_file_offset = 0
        
        for ($i = 0; $i -lt $num_sections; $i++) {
            $sect_name = [Text.Encoding]::ASCII.GetString($br.ReadBytes(8)).TrimEnd([char]0)
            $virt_size = $br.ReadUInt32()
            $virt_addr = $br.ReadUInt32()
            $raw_size = $br.ReadUInt32()
            $raw_ptr = $br.ReadUInt32()
            $fs.Position += 16
            
            if ($debug_rva -ge $virt_addr -and $debug_rva -lt ($virt_addr + $virt_size)) {
                $debug_file_offset = $raw_ptr + ($debug_rva - $virt_addr)
                break
            }
        }
        
        if ($debug_file_offset -eq 0) { $br.Close(); $fs.Close(); return $null }
        
        $fs.Position = $debug_file_offset
        $num_entries = [Math]::Floor($debug_size / 28)
        
        for ($i = 0; $i -lt $num_entries; $i++) {
            $characteristics = $br.ReadUInt32()
            $timestamp = $br.ReadUInt32()
            $major = $br.ReadUInt16()
            $minor = $br.ReadUInt16()
            $type = $br.ReadUInt32()
            $data_size = $br.ReadUInt32()
            $addr_rva = $br.ReadUInt32()
            $addr_ptr = $br.ReadUInt32()
            
            if ($type -eq 2 -and $addr_ptr -ne 0) {
                $save_pos = $fs.Position
                $fs.Position = $addr_ptr
                
                $cv_sig = $br.ReadUInt32()
                if ($cv_sig -eq 0x53445352) {
                    $guid_bytes = $br.ReadBytes(16)
                    $age = $br.ReadUInt32()
                    
                    $pdb_name_bytes = New-Object Collections.Generic.List[byte]
                    while ($true) {
                        $b = $br.ReadByte()
                        if ($b -eq 0) { break }
                        $pdb_name_bytes.Add($b)
                    }
                    $pdb_name = [Text.Encoding]::UTF8.GetString($pdb_name_bytes.ToArray())
                    $pdb_basename = [IO.Path]::GetFileName($pdb_name)
                    
                    $guid = New-Object Guid(,$guid_bytes)
                    $guid_str = $guid.ToString("N").ToUpper()
                    
                    $br.Close(); $fs.Close()
                    return @{
                        name = $pdb_basename
                        guid = $guid_str
                        age = $age
                        sig = "${guid_str}${age}"
                    }
                }
                $fs.Position = $save_pos
            }
        }
        
        $br.Close(); $fs.Close()
        return $null
    } catch {
        return $null
    }
}

function download_pdb([string]$pe_path, [string]$dest_dir, [string]$ts_hex) {
    $pdb = get_pdb_info $pe_path
    if (-not $pdb) { return $false }
    
    $pdb_dst = Join-Path $dest_dir $pdb.name
    if (Test-Path $pdb_dst) { return $true }
    
    $pdb_url = "https://msdl.microsoft.com/download/symbols/$($pdb.name)/$($pdb.sig)/$($pdb.name)"
    
    try {
        Invoke-WebRequest -Uri $pdb_url -OutFile $pdb_dst -UseBasicParsing -EA Stop
        Write-Host "      pdb: $([IO.Path]::GetFileName($pdb_dst))"
        return $true
    } catch {
        Remove-Item $pdb_dst -Force -EA SilentlyContinue
        return $false
    }
}

function get_version_folder($entry) {
    $info = $entry.fileInfo
    $wv = $entry.windowsVersions
    
    if ($info.version) {
        return ($info.version -split ' ')[0]
    }
    
    if ($wv.builds) {
        $first_build = @($wv.builds.PSObject.Properties)[0]
        if ($first_build.Value.updateInfo.build) {
            return $first_build.Value.updateInfo.build
        }
    }
    
    return "unknown_$($info.timestamp)"
}

$base = [IO.Path]::GetFileNameWithoutExtension($file)
$ver_dir = Join-Path $out_dir "${base}_versions"

Write-Host "target: $file"
Write-Host "output: $ver_dir"
Write-Host "arch filter: $arch"
if (-not (Test-Path $ver_dir)) {
    New-Item -ItemType Directory -Path $ver_dir -Force | Out-Null
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$url_main = "https://github.com/m417z/winbindex/raw/gh-pages/data/by_filename_compressed/$file.json.gz"
$url_insider = "https://m417z.com/winbindex-data-insider/by_filename_compressed/$file.json.gz"

$gz_tmp = Join-Path $env:TEMP "$file.json.gz"
$json_tmp = Join-Path $env:TEMP "$file.json"

function fetch_and_decompress([string]$url, [string]$gz_path, [string]$json_path) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $gz_path -UseBasicParsing
        $gz = New-Object IO.FileStream($gz_path, [IO.FileMode]::Open, [IO.FileAccess]::Read)
        $decomp = New-Object IO.Compression.GzipStream($gz, [IO.Compression.CompressionMode]::Decompress)
        $out = New-Object IO.FileStream($json_path, [IO.FileMode]::Create, [IO.FileAccess]::Write)
        $decomp.CopyTo($out)
        $out.Close(); $decomp.Close(); $gz.Close()
        $data = (Get-Content $json_path -Raw) | ConvertFrom-Json
        Remove-Item $gz_path, $json_path -Force -EA SilentlyContinue
        return $data
    } catch {
        Remove-Item $gz_path, $json_path -Force -EA SilentlyContinue
        return $null
    }
}

$meta_main = fetch_and_decompress $url_main $gz_tmp $json_tmp
if (-not $meta_main) {
    Write-Error "download failed for '$file' from main winbindex"
    exit 1
}
$meta_insider = fetch_and_decompress $url_insider $gz_tmp $json_tmp
if ($meta_insider) {
    Write-Host "  insider data found"
} else {
    Write-Host "  no insider data"
}

$merged = @{}
foreach ($e in $meta_main.PSObject.Properties) {
    $merged[$e.Name] = $e.Value
}
if ($meta_insider) {
    foreach ($e in $meta_insider.PSObject.Properties) {
        if (-not $merged.ContainsKey($e.Name)) {
            $merged[$e.Name] = $e.Value
        }
    }
}

$entries = $merged.GetEnumerator()
$total = $merged.Count
Write-Host "found $total versions"

$cache = @{}
$pdb_cache = @{}
$ok = 0; $skip = 0; $fail = 0; $ignored = 0; $pdb_ok = 0; $n = 0

foreach ($e in $entries) {
    $n++
    $v = $e.Value
    $info = $v.fileInfo
    
    if (-not $info) { continue }
    
    $ts = $info.timestamp
    $vs = $info.virtualSize
    if (-not $ts -or -not $vs) { continue }
    
    $bin_arch = get_arch $info.machineType
    if ($arch -ne "all" -and $bin_arch -ne $arch) {
        $ignored++
        continue
    }
    
    $ver = get_version_folder $v
    $ts_hex = "{0:X8}" -f [int64]$ts
    $vs_hex = "{0:X}" -f [int64]$vs
    $sym_url = "https://msdl.microsoft.com/download/symbols/$file/$ts_hex$vs_hex/$file"
    
    $win_vers = @()
    if ($v.windowsVersions) {
        $win_vers = @($v.windowsVersions.PSObject.Properties.Name)
    }
    if ($win_vers.Count -eq 0) { continue }
    
    $key = "${ts}_${vs}"

    # version/timestamp_arch/og_name.ext
    $sub = Join-Path $ver_dir $ver | Join-Path -ChildPath "${ts_hex}_${bin_arch}"
    $base_name = [IO.Path]::GetFileNameWithoutExtension($file)
    $ext = [IO.Path]::GetExtension($file)
    $dst = Join-Path $sub $file
        
    if (Test-Path $dst) {
        Write-Host "[$n/$total] exists: $dst"
        $skip++

        if (-not $skip_pdb -and -not $pdb_cache.ContainsKey($key)) {
            if (download_pdb $dst $sub $ts_hex) { $pdb_ok++; $pdb_cache[$key] = $true }
        }
        continue
    }

    if (-not (Test-Path $sub)) {
        New-Item -ItemType Directory -Path $sub -Force | Out-Null
    }

    if ($cache.ContainsKey($key)) {
        Write-Host "[$n/$total] cache: $dst"
        Copy-Item $cache[$key].bin $dst -Force
        if ($cache[$key].pdb -and (Test-Path $cache[$key].pdb)) {
            Copy-Item $cache[$key].pdb (Join-Path $sub ([IO.Path]::GetFileName($cache[$key].pdb))) -Force
        }
        $ok++
        continue
    }
        
    Write-Host "[$n/$total] get: $sym_url -> $bin_arch"
    $retry = 0; $max_retry = 3; $got = $false
        
    while ($retry -lt $max_retry -and -not $got) {
        try {
            Invoke-WebRequest -Uri $sym_url -OutFile $dst -UseBasicParsing
            $got = $true
            $cache[$key] = @{ bin = $dst; pdb = $null }
            $ok++

            if (-not $skip_pdb) {
                if (download_pdb $dst $sub $ts_hex) {
                    $pdb_ok++
                    $pdb_cache[$key] = $true
                }
            }
        } catch {
            $retry++
            if ($retry -lt $max_retry) {
                Write-Host "  retry $retry/$max_retry..."
                Start-Sleep -Seconds 2
            } else {
                Write-Warning "failed: $sym_url ($_)"
                Remove-Item $dst -Force -EA SilentlyContinue
                $fail++
            }
        }
    }
}

Write-Host ""
Write-Host "binaries - ok: $ok; skip: $skip; fail: $fail; ignored: $ignored"
Write-Host "pdbs: $pdb_ok"
Write-Host "dir: $ver_dir"
