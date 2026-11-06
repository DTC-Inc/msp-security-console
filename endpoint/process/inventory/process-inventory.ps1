## Process Inventory -- endpoint/process/inventory
## Role: inventory (read-only). A snapshot of every process running at the moment the script runs,
## one row per distinct BINARY, published to one hidden NinjaOne field for the security console to
## read into its store. Unattended (SYSTEM), Windows PowerShell 5.1+. Off-agent safe,
## fleet-safe, idempotent. exit 0.
##
## WHY KEYED ON SHA-256
##   The hash is the binary's real identity. The same chrome.exe path holds a different binary after
##   an update, and the same binary can run from several paths (a portable copy, a signed tool
##   dropped into AppData\Temp). Keying on the hash makes both visible: one row per binary, with
##   the list of paths it ran from. 40 copies of chrome.exe are one row with count 40.
##
## UNHASHED PROCESSES ARE KEPT, NEVER DROPPED
##   Kernel pseudo-processes (System, Registry, Memory Compression, Secure System) have no file, and a
##   few protected binaries cannot be read even as SYSTEM. Those rows are keyed by path ("path:...")
##   or, with no path, by name ("name:..."), and carry unhashed = true plus a reason.
##
## CACHE
##   Hash, signature and version info are cached per file under
##   %ProgramData%\DTC\RMM\state\process-inventory-cache.tsv, keyed by path + size + LastWriteTime.
##   A run only re-hashes binaries that changed. Entries not seen for $CacheRetentionDays are pruned.
##   A missing or corrupt cache costs one slower run, never a failure.
##   A cache that is set aside (over $MaxCacheBytes, too big to load under $MaxSelfMB, or the 1.x JSON one) is
##   zipped into state\process-inventory-archive\ first, and archives older than $ArchiveRetentionDays days are deleted.
##
## SERVICES
##   Win32_Service is read once and mapped by the hosting process ID, so every row lists the services
##   its instances were running. One svchost.exe row then says which services that binary hosts.
##
## COMMAND LINES ARE NOT COLLECTED
##   They routinely carry passwords, tokens and connection strings, and this repo never collects or
##   logs secrets. There is deliberately no switch to turn them on.
##
## NINJAONE CUSTOM FIELDS (Device scope, written)
##   processInventory        (WYSIWYG, technician permission NONE) OUT -- base64( gzip( UTF-8 JSON ) ).
##                           Written with Ninja-Property-Set-Piped (stdin): the argument form is bound
##                           by the ~32K Windows command-line limit. The base64 alphabet has no HTML
##                           specials, so the WYSIWYG field cannot rewrite it.
##   processInventoryBytes   (Integer, technician permission NONE) OUT -- length of the stored value in
##                           characters (= bytes). Lets the sync flag devices nearing the field limit.
##   processInventorySummary (Text, technician permission READ_ONLY) OUT -- one line for a human, under
##                           190 characters: counts, unsigned / invalid / unhashed, when, trim level.
##                           Counts describe the whole snapshot even when the payload was trimmed.
##
## PUBLISHING (1.2.0): processInventoryCollectedAt (UTC ISO text) is written EVERY run and is the device's
##   liveness signal. processInventory, processInventoryBytes and processInventorySummary are written only when
##   the content hash changes (binaries, versions, signatures, paths, services) or every 24 hours, so a
##   30-minute schedule doesn't rewrite every device's payload. The payload's collectedAt is the time of the run
##   that published it. processInventoryHash (1.2.1) is the content hash, written after the payload succeeds:
##   a receiver downloads processInventory only when this hash differs from the one it stored.
##   processInventoryChanged (1.2.2) reads "CHANGED <UTC time>" for one run after new content is published
##   and is cleared on the next run, for a NinjaOne custom-field condition ("contains CHANGED", auto-reset)
##   whose webhook tells the receiver which device to sync. The 24-hour refresh never sets it.
##
## RECEIVER CONTRACT (the console: GET /v2/queries/custom-fields-detailed?fields=processInventory)
##   Take the field's text, strip any HTML tags and whitespace the WYSIWYG wrapper adds, then
##   base64-decode -> gunzip -> UTF-8 JSON. Reject a payload whose "schema" is unknown.
##
##   {
##     "schema":        1,                       // bump on any breaking change to this shape
##     "script":        "process-inventory",
##     "scriptVersion": "1.0.0",
##     "collectedAt":   "2026-10-22T14:00:05Z",  // UTC, when the snapshot was taken
##     "hostname":      "WS-0042",
##     "processCount":  212,                     // running processes seen
##     "binaryCount":   97,                      // rows before any trimming
##     "unhashedCount": 6,                       // rows with unhashed = true
##     "unsignedCount": 3,                       // rows whose signatureStatus is NotSigned
##     "invalidSignatureCount": 1,               // rows signed but not Valid (HashMismatch, NotTrusted, ...)
##     "trimmed":       false,                   // true when anything below was left out to fit
##     "trimLevel":     0,                       // 0 none .. 7 overflow, see TRIM LADDER
##     "trimmedFields": [],                      // per-row keys removed, e.g. ["description","firstStart"]
##     "droppedRows":   0,                       // rows removed entirely (trim level 6+)
##     "binaries": [
##       {
##         "key":             "sha256:9f86d0...",  // sha256:<hex> | path:<lower path> | name:<lower name>
##         "sha256":          "9f86d0...",         // lowercase hex, null when unhashed
##         "unhashed":        false,
##         "unhashedReason":  null,                // no-path | unreadable | null
##         "name":            "chrome.exe",
##         "paths":           ["C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"],
##         "pathCount":       1,                   // always present; > paths.Count after trim level 5
##         "fileVersion":     "130.0.6723.59",
##         "product":         "Google Chrome",
##         "company":         "Google LLC",
##         "description":     "Google Chrome",     // first key dropped by the trim ladder
##         "signer":          "Google LLC",        // CN of the signing certificate, null if unsigned
##         "signatureStatus": "Valid",             // Valid | NotSigned | HashMismatch | NotTrusted |
##                                                 // UnknownError | Unavailable (could not be checked)
##         "signatureValid":  true,
##         "signatureSource": "file",              // file | package (an MSIX app signed by its package); null if unhashed
##         "count":           40,                  // running instances of this binary
##         "users":           ["EXAMPLE\\jdoe"],       // distinct owners; empty when not readable
##         "services":        ["Dnscache"],        // Win32_Service names hosted by these instances
##         "firstStart":      "2026-10-22T08:01:12Z" // earliest instance start, UTC; null if unknown
##       }
##     ]
##   }
##
## TRIM LADDER (only when the encoded value would exceed $MaxFieldChars; never cuts the base64)
##   1 drop description   2 drop firstStart   3 drop users   4 drop services
##   5 keep only the first path per row
##   6 drop rows whose signature is Valid (unsigned, invalid and unhashed rows are the ones that
##     matter for detection, so they survive longest)   7 overflow: no rows, counts only.
##
## NOTE -- validate on the pilot:
##   - Ninja-Property-Set-Piped into a WYSIWYG field: NinjaOne documents the piped cmdlet as taking
##     larger values than the 199,999 the argument form allows, without stating a number. The
##     190,000 ceiling here leaves headroom under the documented argument-form limit.
##   - What the API returns for a WYSIWYG value (html vs text) -- the receiver contract above strips
##     tags either way.
##   - First-run time on a busy server: every binary is hashed and signature-checked once.
##
## LOW IMPACT (1.3.0)
##   On 2026-10-27, 1.2.2 ran two client server VMs out of memory and locked them up. Since then
##   the script stays in the background and backs off:
##   - one instance at a time (a Global mutex): a run that finds another one still going exits at once;
##   - Below Normal priority for its own process;
##   - a memory guard: with free physical memory under $MinFreeMemoryPercent % or $MinFreeMemoryMB MB, it
##     collects nothing and exits;
##   - the Store-package signer lookup only when a running binary is under \WindowsApps\, and never on a
##     server (Get-AppxPackage -AllUsers walks every profile, which on a terminal server is most of the RAM spent);
##   - (1.3.2) the identity cache is a line-per-entry file read as a stream, and a cache over $MaxCacheBytes is
##     dropped, not read. Parsing the 1.x JSON cache whole was what ran a Server 2019 VM out of memory.
##   - (1.3.3) the cache may grow to $MaxCacheBytes (100 MB), and a cache set aside is
##     kept as a zip for 30 days. Loading stops early if the script's own memory nears $MaxSelfMB, and a cache
##     set aside is zipped, not deleted.
##   - (1.3.1) its own memory is logged after every phase and checked as it goes; past $MaxSelfMB MB the run stops
##     without publishing, so whatever grows can never take the server down again. The phase log says where.
##   - at most $MaxNewIdentitiesPerRun new hash + signature checks per run, within $TimeBudgetSeconds s; the rest are
##     marked unhashed 'deferred' and done on later runs (the cache keeps what's done).
##
## EXIT CODE: 0 (inventory -- always; a failed write is logged as a warning).

# ============================================================
# STATIC CONFIG -- edit on fork to match your NinjaOne instance
# ============================================================
$FieldProcessInventory        = "processInventory"          # WYSIWYG, hidden from technicians
$FieldProcessInventoryBytes   = "processInventoryBytes"     # Integer
$FieldProcessInventorySummary = "processInventorySummary"   # Text, readable by technicians
$FieldProcessInventoryCollectedAt = "processInventoryCollectedAt"  # Text (UTC ISO), written EVERY run: the liveness signal
$FieldProcessInventoryHash = "processInventoryHash"   # Text, the content hash, written WITH the payload: what a receiver compares
$FieldProcessInventoryChanged = "processInventoryChanged"  # Text, "CHANGED <time>" for one run after the content changes, else empty

$ScriptName    = 'process-inventory'
$ScriptVersion = '1.3.3'
$SchemaVersion = 1

# On-disk layout -- see CLAUDE.md, "On-disk state and tool binaries".
$DtcRmmRoot  = Join-Path $env:ProgramData 'DTC\RMM'
$DtcStateDir = Join-Path $DtcRmmRoot 'state'
# 1.3.2: one entry per line (TSV), read and written as a stream. The 1.x JSON cache was parsed whole with
# ConvertFrom-Json, which on Windows PowerShell 5.1 needs many times the file's size: on 2026-10-27 that single
# call took a Server 2019 VM's RAM (the run's log stopped after "phase services"). The old file is removed unread.
$CacheFile   = Join-Path $DtcStateDir 'process-inventory-cache.tsv'
$LegacyCacheFile = Join-Path $DtcStateDir 'process-inventory-cache.json'
$MaxCacheBytes = 100MB
# 1.3.3: a cache that is set aside is zipped here rather than deleted, and kept $ArchiveRetentionDays days.
$CacheArchiveDir = Join-Path $DtcStateDir 'process-inventory-archive'
$ArchiveRetentionDays = 30
$PublishStateFile = Join-Path $DtcStateDir 'process-inventory-published.json'

# Operational tunables. Static defaults so the script runs unattended with no input.
# Ceiling for the encoded value; NinjaOne's documented WYSIWYG limit is 199,999 characters.
$MaxFieldChars      = if ($env:ProcessInventoryMaxChars) { [int]$env:ProcessInventoryMaxChars } else { 190000 }
$CacheRetentionDays = 30
# The big field is rewritten only when the content changes, or at least this often so the datalake's 30-day
# retention never ages out a quiet device (the script runs every 30 minutes; processInventoryCollectedAt says when it last ran).
$FullRefreshHours   = 24
# Low impact (1.3.0): back off rather than compete with the server's own work.
$MinFreeMemoryPercent   = 20
$MinFreeMemoryMB        = 1024
$MaxNewIdentitiesPerRun = 40
$TimeBudgetSeconds      = 120
$MutexName              = 'Global\DTC-RMM-process-inventory'
# 1.3.1: a hard ceiling on the script's OWN memory. 1.3.0 still grew until a Server 2016 VM ran out of RAM,
# so the cause is inside one run. Past this, the run stops without publishing.
$MaxSelfMB              = 400

# ============================================================
# HELPERS (off-agent safe)
# ============================================================
function Set-NinjaField {
    param([string]$Name, [string]$Value)
    if (-not $Name) { return $false }
    if (-not (Get-Command 'Ninja-Property-Set' -ErrorAction SilentlyContinue)) {
        Write-Host "  [off-agent] would set $Name"; return $false
    }
    try {
        # Ninja-Property-Set reports failure (missing/unwritable field, off-agent shim) as OUTPUT
        # text WITHOUT throwing -- inspect merged output, else a failed write masquerades as success.
        $out = (Ninja-Property-Set $Name $Value 2>&1 | Out-String).Trim()
        if ($out -match 'Unable to find|does not exist|not a valid|ninjarmm-cli') {
            Write-Warning "  Failed to write $Name : $out"; return $false
        }
        Write-Host "  [ok] $Name updated."; return $true
    } catch { Write-Warning "  Failed to write $Name : $_"; return $false }
}

# Large values go on STDIN: the argument form is capped by the Windows command line (~32K chars),
# far below the WYSIWYG limit. Same shape as backup/veeam/inventory/veeam-inventory.ps1. Logs the
# length only, never the value.
function Set-NinjaFieldPiped {
    param([string]$Name, [string]$Value)
    if (-not $Name) { return $false }
    if (-not (Get-Command 'Ninja-Property-Set-Piped' -ErrorAction SilentlyContinue)) {
        if (Get-Command 'Ninja-Property-Set' -ErrorAction SilentlyContinue) {
            Write-Warning "  Ninja-Property-Set-Piped unavailable; falling back to the argument form for $Name ($($Value.Length) chars)."
            return (Set-NinjaField -Name $Name -Value $Value)
        }
        Write-Host "  [off-agent] would set $Name ($($Value.Length) chars, piped)"
        return $false
    }
    try {
        $out = ($Value | Ninja-Property-Set-Piped $Name 2>&1 | Out-String).Trim()
        if ($out -match 'Unable to find|does not exist|not a valid|ninjarmm-cli') {
            Write-Warning "  Failed to write $Name : $out"; return $false
        }
        Write-Host "  [ok] $Name updated ($($Value.Length) chars, piped)."; return $true
    } catch { Write-Warning "  Failed to write $Name : $_"; return $false }
}

# ============================================================
# PURE LOGIC -- unit-tested in endpoint/process/scripts/test-process-inventory.ps1
# ============================================================

function ConvertTo-IsoUtc {
    param($Date)
    if ($null -eq $Date) { return $null }
    try { return ([datetime]$Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return $null }
}

# Memory guard (1.3.0): enough headroom to run? Inputs in KB, as Win32_OperatingSystem reports them. Unknown
# values (0 or null) mean "can't tell", which runs: the guard is for a box that is visibly short of memory.
function Test-MemoryHeadroom {
    param([double]$FreeKB, [double]$TotalKB, [int]$MinPercent, [int]$MinMB)
    if ($FreeKB -le 0 -or $TotalKB -le 0) { return $true }
    if (($FreeKB / 1024) -lt $MinMB) { return $false }
    if ((100 * $FreeKB / $TotalKB) -lt $MinPercent) { return $false }
    return $true
}

# The script's own working set in MB (1.3.1). Refresh() first, or .NET returns the value from the last read.
function Get-SelfMB {
    try { $me = [System.Diagnostics.Process]::GetCurrentProcess(); $me.Refresh(); return [math]::Round($me.WorkingSet64 / 1MB) } catch { return 0 }
}

# Over the ceiling? Pure, so the tests can hold it to the rule.
function Test-OverSelfCap { param([double]$MB, [int]$CapMB) return ($CapMB -gt 0 -and $MB -gt $CapMB) }

# Store-package lookup (1.3.0): only when a running binary is inside \WindowsApps\, and never on a server.
function Test-NeedPackageMap {
    param([string[]]$Paths, [bool]$IsServer)
    if ($IsServer) { return $false }
    foreach ($p in @($Paths)) { if ($p -and "$p".ToLowerInvariant().Contains('\windowsapps\')) { return $true } }
    return $false
}

# Group key for one process. Hash first; else lowercased path; else lowercased name.
function Get-ProcessKey {
    param([string]$Sha256, [string]$Path, [string]$Name)
    if ($Sha256) { return "sha256:$($Sha256.ToLowerInvariant())" }
    if ($Path)   { return "path:$($Path.ToLowerInvariant())" }
    return "name:$("$Name".ToLowerInvariant())"
}

# Collapse per-process records into one row per binary. Each record is a hashtable/object with:
#   Name, Path, User, StartTime, Services (service names it hosts, may be empty), and the file
#   identity (Sha256, FileVersion, Product, Company, Description, Signer, SignatureStatus,
#   UnhashedReason) -- identity is null-safe.
# Returns an array of [ordered] rows, sorted by key so output is stable run to run.
function Group-ProcessRecords {
    param([object[]]$Records)
    $groups = @{}
    $order  = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Records)) {
        if ($null -eq $r) { continue }
        $key = Get-ProcessKey -Sha256 $r.Sha256 -Path $r.Path -Name $r.Name
        if (-not $groups.ContainsKey($key)) {
            $reason = $null
            if (-not $r.Sha256) { $reason = if ($r.Path) { if ($r.UnhashedReason) { "$($r.UnhashedReason)" } else { 'unreadable' } } else { 'no-path' } }
            $groups[$key] = @{
                Key = $key; Sha256 = $(if ($r.Sha256) { "$($r.Sha256)".ToLowerInvariant() } else { $null })
                Reason = $reason; Name = "$($r.Name)"
                Paths = New-Object System.Collections.Generic.List[string]
                PathSeen = @{}
                FileVersion = $r.FileVersion; Product = $r.Product; Company = $r.Company
                Description = $r.Description; Signer = $r.Signer; SignatureStatus = $r.SignatureStatus
                SignatureSource = $(if ($r.SignatureSource) { "$($r.SignatureSource)" } else { 'file' })
                Count = 0
                Users = New-Object System.Collections.Generic.List[string]
                UserSeen = @{}
                Services = New-Object System.Collections.Generic.List[string]
                ServiceSeen = @{}
                First = $null
            }
            $order.Add($key)
        }
        $g = $groups[$key]
        $g.Count++
        if ($r.Path) {
            $pk = "$($r.Path)".ToLowerInvariant()
            if (-not $g.PathSeen.ContainsKey($pk)) { $g.PathSeen[$pk] = $true; $g.Paths.Add("$($r.Path)") }
        }
        if ($r.User) {
            $uk = "$($r.User)".ToLowerInvariant()
            if (-not $g.UserSeen.ContainsKey($uk)) { $g.UserSeen[$uk] = $true; $g.Users.Add("$($r.User)") }
        }
        foreach ($s in @($r.Services)) {
            if (-not $s) { continue }
            $sk = "$s".ToLowerInvariant()
            if (-not $g.ServiceSeen.ContainsKey($sk)) { $g.ServiceSeen[$sk] = $true; $g.Services.Add("$s") }
        }
        if ($null -ne $r.StartTime) {
            try {
                $st = ([datetime]$r.StartTime).ToUniversalTime()
                if ($null -eq $g.First -or $st -lt $g.First) { $g.First = $st }
            } catch { }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($key in ($order | Sort-Object)) {
        $g = $groups[$key]
        $sig = if ($g.Sha256) { if ($g.SignatureStatus) { "$($g.SignatureStatus)" } else { 'Unavailable' } } else { $null }
        $rows.Add([ordered]@{
            key             = $g.Key
            sha256          = $g.Sha256
            unhashed        = [bool](-not $g.Sha256)
            unhashedReason  = $g.Reason
            name            = $g.Name
            paths           = [string[]]@($g.Paths | Sort-Object)
            pathCount       = $g.Paths.Count
            fileVersion     = $(if ($g.FileVersion) { "$($g.FileVersion)" } else { $null })
            product         = $(if ($g.Product)     { "$($g.Product)" }     else { $null })
            company         = $(if ($g.Company)     { "$($g.Company)" }     else { $null })
            description     = $(if ($g.Description) { "$($g.Description)" } else { $null })
            signer          = $(if ($g.Signer)      { "$($g.Signer)" }      else { $null })
            signatureStatus = $sig
            signatureValid  = [bool]($sig -eq 'Valid')
            signatureSource = $(if ($g.Sha256) { $g.SignatureSource } else { $null })
            count           = $g.Count
            users           = [string[]]@($g.Users | Sort-Object)
            services        = [string[]]@($g.Services | Sort-Object)
            firstStart      = $(if ($null -ne $g.First) { $g.First.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null })
        })
    }
    return ,($rows.ToArray())
}

function New-InventoryDocument {
    param([object[]]$Rows, [int]$ProcessCount, [string]$Hostname, [datetime]$CollectedAt)
    $rowsArr = @($Rows)
    return [ordered]@{
        schema        = $SchemaVersion
        script        = $ScriptName
        scriptVersion = $ScriptVersion
        collectedAt   = (ConvertTo-IsoUtc $CollectedAt)
        hostname      = $Hostname
        processCount  = $ProcessCount
        binaryCount   = $rowsArr.Count
        unhashedCount = @($rowsArr | Where-Object { $_.unhashed }).Count
        unsignedCount = @($rowsArr | Where-Object { $_.signatureStatus -eq 'NotSigned' }).Count
        invalidSignatureCount = @($rowsArr | Where-Object { $_.signatureStatus -and $_.signatureStatus -notin @('Valid','NotSigned','Unavailable') }).Count
        trimmed       = $false
        trimLevel     = 0
        trimmedFields = [string[]]@()
        droppedRows   = 0
        binaries      = [object[]]$rowsArr
    }
}

# JSON -> gzip -> base64. UTF-8 without BOM so the receiver's JSON parser sees "{" first.
function ConvertTo-CompressedBase64 {
    param([string]$Text)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    try { $gz.Write($bytes, 0, $bytes.Length) } finally { $gz.Dispose() }
    return [Convert]::ToBase64String($ms.ToArray())
}

# The inverse, exactly what the console's receiver does. Used by the tests; documents the contract.
function ConvertFrom-CompressedBase64 {
    param([string]$Base64)
    $clean = ($Base64 -replace '<[^>]*>', '') -replace '\s', ''
    $in  = New-Object System.IO.MemoryStream(, [Convert]::FromBase64String($clean))
    $gz  = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    try { $gz.CopyTo($out) } finally { $gz.Dispose() }
    return (New-Object System.Text.UTF8Encoding($false)).GetString($out.ToArray())
}

function ConvertTo-PayloadJson {
    param($Document)
    return ($Document | ConvertTo-Json -Depth 6 -Compress)
}

# Encode the document; if it would not fit, walk the trim ladder one rung at a time until it does.
# Returns @{ Value = <base64>; Document = <the document actually encoded>; Level = <rung> }.
# The base64 is never cut: every rung re-encodes a smaller, complete document.
function Get-FittedPayload {
    param($Document, [int]$MaxChars)
    $doc = $Document
    $value = ConvertTo-CompressedBase64 (ConvertTo-PayloadJson $doc)
    if ($value.Length -le $MaxChars) { return @{ Value = $value; Document = $doc; Level = 0 } }

    $dropKeys = @{ 1 = 'description'; 2 = 'firstStart'; 3 = 'users'; 4 = 'services' }
    $fields = New-Object System.Collections.Generic.List[string]
    for ($level = 1; $level -le 7; $level++) {
        $rows = @($doc.binaries)
        if ($dropKeys.ContainsKey($level)) {
            $k = $dropKeys[$level]
            foreach ($r in $rows) { if ($r.Contains($k)) { $r.Remove($k) } }
            $fields.Add($k)
        } elseif ($level -eq 5) {
            foreach ($r in $rows) { if (@($r.paths).Count -gt 1) { $r.paths = [string[]]@(@($r.paths)[0]) } }
            $fields.Add('paths')
        } elseif ($level -eq 6) {
            $keep = @($rows | Where-Object { -not $_.signatureValid })
            $doc.droppedRows = $rows.Count - $keep.Count
            $doc.binaries = [object[]]$keep
        } else {
            $doc.droppedRows = $doc.binaryCount
            $doc.binaries = [object[]]@()
        }
        $doc.trimmed = $true
        $doc.trimLevel = $level
        $doc.trimmedFields = [string[]]$fields.ToArray()
        $value = ConvertTo-CompressedBase64 (ConvertTo-PayloadJson $doc)
        if ($value.Length -le $MaxChars) { return @{ Value = $value; Document = $doc; Level = $level } }
    }
    # Level 7 is counts only and is a few hundred characters; reaching here means MaxChars is absurd.
    return @{ Value = $value; Document = $doc; Level = 7 }
}

# The one line a technician reads in NinjaOne. Built from the document's counts, which are taken
# before any trimming, so it describes the whole snapshot even when the payload was trimmed.
# Example: "212 procs, 97 binaries | unsigned 3, invalid sig 1, unhashed 6 | 2026-10-22 14:00Z"
function Get-InventorySummary {
    param($Document, [int]$Level, [int]$MaxLength = 189)
    # No timestamp: the summary is written only when the content changes; when it was last seen is
    # processInventoryCollectedAt, written every run.
    $line = '{0} procs, {1} binaries | unsigned {2}, invalid sig {3}, unhashed {4}' -f `
        $Document.processCount, $Document.binaryCount, $Document.unsignedCount,
        $Document.invalidSignatureCount, $Document.unhashedCount
    if ($Level -gt 0) { $line += " | trimmed L$Level" }
    if ($line.Length -gt $MaxLength) { $line = $line.Substring(0, $MaxLength) }
    return $line
}

# What "changed" means for publishing: the set of binaries and what identifies them (key, version, signer and
# signature, paths, hosted services). Instance counts, users, start times, the process count and collectedAt move
# whenever a process restarts, so they are left out; otherwise a 30-minute schedule would rewrite every device's
# field every run. Order-independent.
function Get-ContentHash {
    param($Document)
    $items = foreach ($b in @($Document.binaries)) {
        if ($null -eq $b) { continue }
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $b.key, $b.fileVersion, $b.signer, $b.signatureStatus, $b.signatureSource,
            ((@($b.paths) | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join ';'),
            ((@($b.services) | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object) -join ';')
    }
    $text = (@($items) | Sort-Object) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}

# Publish the big field when nothing was published yet, the content changed, or the last publish is older than
# $MaxAgeHours (or unreadable).
function Test-ShouldPublish {
    param($State, [string]$Hash, [datetime]$Now, [int]$MaxAgeHours = 24)
    if (-not $State -or -not $State.hash -or "$($State.hash)" -ne $Hash) { return $true }
    $at = $null
    try {
        if ($State.publishedAt -is [datetime]) { $at = $State.publishedAt.ToUniversalTime() }
        else { $at = [datetime]::Parse("$($State.publishedAt)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
    } catch { return $true }
    return (($Now.ToUniversalTime() - $at).TotalHours -ge $MaxAgeHours)
}

# The change flag (1.2.2) a NinjaOne custom-field condition matches with "contains CHANGED" (NinjaOne's
# conditions compare values; they cannot fire on "changed"). 'set' when a new hash was published, 'clear' on the
# next run so the condition resets, 'none' otherwise. The 24-hour refresh of unchanged content never sets it.
function Get-ChangeFlagAction {
    param($State, [string]$Hash, [bool]$Published)
    $prevHash = if ($State) { "$($State.hash)" } else { '' }
    if ($Published -and $prevHash -ne $Hash) { return 'set' }
    if ($State -and $State.flagSet) { return 'clear' }
    return 'none'
}

# ---- Cache: path + size + LastWriteTime -> hash, signature, version info ----

# One cache entry per line, tab-separated, in this column order. A value never carries a tab or a newline (they are
# replaced by spaces on write), so a line always splits back into the same columns.
$CacheColumns = @('path','size','mtimeTicks','sha256','signer','signatureStatus','fileVersion','product','company','description','lastSeen')

# 1.3.3: zip a state file into $ArchiveDir before it is set aside. Streams the file into the zip, so even a 100 MB cache
# costs almost no memory. Returns the zip's path, or $null when it could not be made (the caller removes the file anyway:
# memory safety comes before keeping a copy).
function Save-StateArchive {
    param([string]$Path, [string]$ArchiveDir, [datetime]$Now)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path) -or -not $ArchiveDir) { return $null }
    $za = $null
    try {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $ArchiveDir)) { New-Item -ItemType Directory -Path $ArchiveDir -Force | Out-Null }
        $base = '{0}-{1}' -f [System.IO.Path]::GetFileName($Path), $Now.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        $zip = Join-Path $ArchiveDir "$base.zip"
        $n = 1
        while (Test-Path -LiteralPath $zip) { $zip = Join-Path $ArchiveDir "$base-$n.zip"; $n++ }
        $za = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Create)
        $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($za, $Path, [System.IO.Path]::GetFileName($Path), [System.IO.Compression.CompressionLevel]::Optimal)
        $za.Dispose(); $za = $null
        Write-Host ("  Archived {0} ({1:N0} bytes) to {2} ({3:N0} bytes)." -f [System.IO.Path]::GetFileName($Path), (Get-Item -LiteralPath $Path).Length, $zip, (Get-Item -LiteralPath $zip).Length)
        return $zip
    } catch {
        if ($za) { try { $za.Dispose() } catch { } }
        Write-Host "  Could not archive $Path : $($_.Exception.Message)"
        return $null
    }
}

# 1.3.3: archives older than $Days are deleted. Returns how many went.
function Remove-OldArchives {
    param([string]$ArchiveDir, [int]$Days, [datetime]$Now)
    if (-not $ArchiveDir -or -not (Test-Path -LiteralPath $ArchiveDir)) { return 0 }
    $cutoff = $Now.ToUniversalTime().AddDays(-$Days)
    $gone = 0
    foreach ($z in @(Get-ChildItem -LiteralPath $ArchiveDir -Filter '*.zip' -File -ErrorAction SilentlyContinue)) {
        if ($z.LastWriteTimeUtc -lt $cutoff) { try { Remove-Item -LiteralPath $z.FullName -Force -ErrorAction Stop; $gone++ } catch { } }
    }
    return $gone
}

function Read-IdentityCache {
    param([string]$Path, [long]$MaxBytes = 100MB, [string]$ArchiveDir, [int]$StopAtMB = 0, [datetime]$Now = (Get-Date))
    $cache = @{}
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $cache }
    try {
        $len = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length
        if ($MaxBytes -gt 0 -and $len -gt $MaxBytes) {
            Write-Host ("  Cache is {0:N0} bytes (over {1:N0}); archiving it unread, starting fresh." -f $len, $MaxBytes)
            $null = Save-StateArchive -Path $Path -ArchiveDir $ArchiveDir -Now $Now
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            return $cache
        }
        $lines = 0; $stopped = $false
        # An explicit enumerator, so the file is closed before it is archived and removed.
        $en = [System.IO.File]::ReadLines($Path).GetEnumerator()
        try {
            while ($en.MoveNext()) {
                $line = $en.Current
                # 1.3.3: a 100 MB cache holds far more entries than fit under the memory cap once loaded, so loading
                # stops while there is room left for the run. The whole file is archived; what was loaded is written back.
                if ($StopAtMB -gt 0 -and (++$lines % 2000) -eq 0 -and (Get-SelfMB) -gt $StopAtMB) { $stopped = $true; break }
                if (-not $line -or $line.StartsWith('#')) { continue }
                $f = $line.Split("`t")
                if ($f.Count -ne $CacheColumns.Count -or -not $f[0]) { continue }
                $h = @{}
                for ($i = 0; $i -lt $f.Count; $i++) { $h[$CacheColumns[$i]] = $(if ($f[$i] -eq '') { $null } else { $f[$i] }) }
                $cache["$($h.path)".ToLowerInvariant()] = $h
            }
        } finally { $en.Dispose() }
        if ($stopped) {
            Write-Host ("  Cache loading stopped at {0:N0} entries (self over {1} MB); archiving the full file." -f $cache.Count, $StopAtMB)
            $null = Save-StateArchive -Path $Path -ArchiveDir $ArchiveDir -Now $Now
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "  Cache unreadable, starting fresh: $($_.Exception.Message)"
        $cache = @{}
    }
    return $cache
}

function Write-IdentityCache {
    param([hashtable]$Cache, [string]$Path, [int]$RetentionDays, [datetime]$Now)
    $w = $null
    try {
        $cutoff = $Now.ToUniversalTime().AddDays(-$RetentionDays)
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $tmp = "$Path.tmp"
        $w = New-Object System.IO.StreamWriter($tmp, $false, (New-Object System.Text.UTF8Encoding($false)))
        $w.WriteLine('#v2 ' + ($CacheColumns -join "`t"))
        $count = 0
        foreach ($k in $Cache.Keys) {
            $e = $Cache[$k]
            $seen = $null
            try {
                if ($e.lastSeen -is [datetime]) { $seen = $e.lastSeen.ToUniversalTime() }
                else { $seen = [datetime]::Parse("$($e.lastSeen)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) }
            } catch { }
            if ($null -eq $seen -or $seen -lt $cutoff -or -not $e.path) { continue }
            $vals = foreach ($c in $CacheColumns) {
                $v = if ($c -eq 'lastSeen') { $seen.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $e[$c] }
                ("$v" -replace "[`t`r`n]", ' ')
            }
            $w.WriteLine(($vals -join "`t"))
            $count++
        }
        $w.Dispose(); $w = $null
        Move-Item -LiteralPath $tmp -Destination $Path -Force
        return $count
    } catch {
        if ($w) { try { $w.Dispose() } catch { } }
        Write-Warning "  Could not write cache $Path : $($_.Exception.Message)"
        return -1
    }
}

function Get-SignatureInfo {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $signer = $null
        if ($sig.SignerCertificate) {
            $subj = "$($sig.SignerCertificate.Subject)"
            if ($subj -match '(?:^|,\s*)CN=("([^"]+)"|[^,]+)') { $signer = if ($matches[2]) { $matches[2] } else { $matches[1].Trim() } }
            else { $signer = $subj }
        }
        return @{ Signer = $signer; Status = "$($sig.Status)" }
    } catch {
        return @{ Signer = $null; Status = 'Unavailable' }
    }
}

# MSIX (Microsoft Store and inbox) apps are signed at the package, in AppxSignature.p7x, not in each
# file, so Get-AuthenticodeSignature reports their executables NotSigned (the 2026-10-26 pilot: three
# of four "unsigned" binaries were Store apps). Windows verifies the package signature at install and
# the block map at load, so a file inside a Store, System or Enterprise package counts as Valid, signed
# by the package publisher. Developer (sideloaded) packages and files outside any package keep their
# own result, and a file whose OWN signature is broken is never upgraded.
function ConvertTo-PackageSignerMap {
    param([object[]]$Packages)
    $map = @{}
    foreach ($pkg in @($Packages)) {
        if (-not $pkg -or -not $pkg.InstallLocation) { continue }
        $loc = "$($pkg.InstallLocation)".TrimEnd('\').ToLowerInvariant() + '\'
        $map[$loc] = @{ Publisher = "$($pkg.Publisher)"; Kind = "$($pkg.SignatureKind)" }
    }
    return $map
}

function Get-PackageSignerMap {
    try { return ConvertTo-PackageSignerMap -Packages @(Get-AppxPackage -AllUsers -ErrorAction Stop) }
    catch { Write-Host "  Appx packages unavailable ($($_.Exception.Message)); Store apps keep their file signature result."; return @{} }
}

function Resolve-PackageSignature {
    param([string]$Path, $Signer, $Status, [hashtable]$PackageMap)
    $out = @{ Signer = $Signer; Status = $Status; Source = 'file' }
    if ("$Status" -ne 'NotSigned' -or -not $Path -or -not $PackageMap -or $PackageMap.Count -eq 0) { return $out }
    $lp = $Path.ToLowerInvariant()
    $best = $null
    foreach ($loc in $PackageMap.Keys) {
        if ($lp.StartsWith($loc) -and ($null -eq $best -or $loc.Length -gt $best.Length)) { $best = $loc }
    }
    if (-not $best) { return $out }
    $pkg = $PackageMap[$best]
    if ($pkg.Kind -notin @('Store','System','Enterprise')) { return $out }
    $pub = $pkg.Publisher
    if ($pub -match '(?:^|,\s*)CN=("([^"]+)"|[^,]+)') { $pub = if ($matches[2]) { $matches[2] } else { $matches[1].Trim() } }
    return @{ Signer = $pub; Status = 'Valid'; Source = 'package' }
}

# Identity of one file, from the cache when path + size + LastWriteTime match, else computed and
# stored. Returns a hashtable; Sha256 is null with UnhashedReason when the file cannot be read.
# Counters in $Stats (Hits / Misses / Failures) let the run log say how much work the cache saved.
function Get-FileIdentity {
    param([string]$Path, [hashtable]$Cache, [hashtable]$Stats, [datetime]$Now, [hashtable]$Budget)
    $nowIso = ConvertTo-IsoUtc $Now
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    } catch {
        if ($Stats) { $Stats.Failures++ }
        return @{ Sha256 = $null; UnhashedReason = 'unreadable' }
    }
    $size  = [int64]$fi.Length
    $ticks = [int64]$fi.LastWriteTimeUtc.Ticks
    $ck = $Path.ToLowerInvariant()
    if ($Cache -and $Cache.ContainsKey($ck)) {
        $e = $Cache[$ck]
        if ([int64]$e.size -eq $size -and [int64]$e.mtimeTicks -eq $ticks -and $e.sha256) {
            $e.lastSeen = $nowIso
            if ($Stats) { $Stats.Hits++ }
            return @{ Sha256 = $e.sha256; FileVersion = $e.fileVersion; Product = $e.product; Company = $e.company
                      Description = $e.description; Signer = $e.signer; SignatureStatus = $e.signatureStatus; UnhashedReason = $null }
        }
    }
    # Bounded work per run (1.3.0): past the budget, the file waits for a later run.
    if ($Budget) {
        if ($Budget.Left -le 0 -or (Get-Date) -gt $Budget.Deadline) {
            if ($Stats) { $Stats.Deferred++ }
            return @{ Sha256 = $null; UnhashedReason = 'deferred' }
        }
        $Budget.Left--
    }
    try {
        $sha = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    } catch {
        if ($Stats) { $Stats.Failures++ }
        return @{ Sha256 = $null; UnhashedReason = 'unreadable' }
    }
    $ver = $null
    try { $ver = $fi.VersionInfo } catch { }
    $sig = Get-SignatureInfo -Path $Path
    $id = @{
        Sha256 = $sha
        FileVersion = $(if ($ver -and $ver.FileVersion) { "$($ver.FileVersion)".Trim() } else { $null })
        Product     = $(if ($ver -and $ver.ProductName) { "$($ver.ProductName)".Trim() } else { $null })
        Company     = $(if ($ver -and $ver.CompanyName) { "$($ver.CompanyName)".Trim() } else { $null })
        Description = $(if ($ver -and $ver.FileDescription) { "$($ver.FileDescription)".Trim() } else { $null })
        Signer = $sig.Signer; SignatureStatus = $sig.Status; UnhashedReason = $null
    }
    if ($Cache) {
        $Cache[$ck] = @{ path = $Path; size = $size; mtimeTicks = $ticks; sha256 = $sha
            signer = $id.Signer; signatureStatus = $id.SignatureStatus; fileVersion = $id.FileVersion
            product = $id.Product; company = $id.Company; description = $id.Description; lastSeen = $nowIso }
    }
    if ($Stats) { $Stats.Misses++ }
    return $id
}

# ============================================================
# LOGGING (guarded transcript)
# ============================================================
$ScriptLogName = "process-inventory.log"
if ($env:RMM_SCRIPT_PATH) {
    $LogDir = "$env:RMM_SCRIPT_PATH\logs"
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $LogPath = "$LogDir\$ScriptLogName"
} elseif ($env:WINDIR) {
    $LogPath = "$env:WINDIR\logs\$ScriptLogName"
} else {
    $LogPath = Join-Path ([System.IO.Path]::GetTempPath()) $ScriptLogName   # off-Windows dry run only
}
$TranscriptStarted = $false
try { Start-Transcript -Path $LogPath -ErrorAction Stop | Out-Null; $TranscriptStarted = $true }
catch { Write-Host "Warning: Could not start transcript at $LogPath - $($_.Exception.Message)" }

Write-Host "=== Process inventory v$ScriptVersion ==="
$now = Get-Date

# ============================================================
# LOW IMPACT (1.3.0): one instance, background priority, a memory guard
# ============================================================
$mutex = $null
try {
    $mutex = New-Object System.Threading.Mutex($false, $MutexName)
    $owned = $false
    try { $owned = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) {
        Write-Host "Another process-inventory run is still going; exiting without collecting."
        if ($TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
        exit 0
    }
} catch { Write-Host "  Mutex unavailable ($($_.Exception.Message)); continuing." ; $mutex = $null }
try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal } catch { }
$isServer = $false
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $isServer = ([int]$os.ProductType -ne 1)
    if (-not (Test-MemoryHeadroom -FreeKB ([double]$os.FreePhysicalMemory) -TotalKB ([double]$os.TotalVisibleMemorySize) -MinPercent $MinFreeMemoryPercent -MinMB $MinFreeMemoryMB)) {
        Write-Host ("Low memory: {0:N0} MB free of {1:N0} MB; skipping this run." -f ($os.FreePhysicalMemory / 1024), ($os.TotalVisibleMemorySize / 1024))
        if ($mutex) { try { $mutex.ReleaseMutex() } catch { } }
        if ($TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
        exit 0
    }
} catch { Write-Host "  Win32_OperatingSystem unavailable ($($_.Exception.Message)); memory guard skipped." }
$budget = @{ Left = $MaxNewIdentitiesPerRun; Deadline = (Get-Date).AddSeconds($TimeBudgetSeconds) }

# Phase log and the hard ceiling (1.3.1). Logs where memory goes; past $MaxSelfMB MB, stops without publishing.
function Step-Phase {
    param([string]$Phase)
    $mb = Get-SelfMB
    # The whole machine's free memory too: the growth can be in a process this script drives (WmiPrvSE for the CIM
    # queries, CryptSvc for signatures, Defender scanning each file it hashes), which its own working set never shows.
    $freeMB = 0; $totMB = 0
    try { $o = Get-CimInstance -ClassName Win32_OperatingSystem -Property FreePhysicalMemory, TotalVisibleMemorySize -ErrorAction Stop; $freeMB = [math]::Round($o.FreePhysicalMemory / 1024); $totMB = [math]::Round($o.TotalVisibleMemorySize / 1024) } catch { }
    Write-Host ("  phase {0}: self {1} MB | machine free {2} of {3} MB" -f $Phase, $mb, $freeMB, $totMB)
    $machineLow = ($totMB -gt 0) -and -not (Test-MemoryHeadroom -FreeKB ($freeMB * 1024) -TotalKB ($totMB * 1024) -MinPercent $MinFreeMemoryPercent -MinMB $MinFreeMemoryMB)
    if ((Test-OverSelfCap -MB $mb -CapMB $MaxSelfMB) -or $machineLow) {
        Write-Host ("Memory limit hit in phase '{0}': self {1} MB (cap {2}), machine free {3} MB. Stopping without publishing." -f $Phase, $mb, $MaxSelfMB, $freeMB)
        if ($mutex) { try { $mutex.ReleaseMutex() } catch { } }
        if ($TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
        exit 0
    }
}
Write-Host ("PowerShell {0} | OS {1} | server: {2}" -f $PSVersionTable.PSVersion, $(try { [System.Environment]::OSVersion.Version } catch { '?' }), $isServer)
Step-Phase 'start'

# ============================================================
# COLLECTION -- one record per running process; a failure on one never aborts the run
# ============================================================
# Win32_Process gives the executable path and creation time for processes Get-Process cannot open.
# Get-Process -IncludeUserName gives the owner in one call (GetOwner per process is far slower).
$procs = @()
$cimOk = $false
try {
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
        Select-Object ProcessId, Name, ExecutablePath, CreationDate)
    $cimOk = $true
} catch {
    Write-Host "  Win32_Process unavailable ($($_.Exception.Message)); using Get-Process."
}

$gp = @{}
try {
    foreach ($p in @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue)) { $gp[[int]$p.Id] = $p }
} catch {
    try { foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $gp[[int]$p.Id] = $p } } catch { }
}
if (-not $cimOk) {
    $procs = @($gp.Values | ForEach-Object {
        $path = $null; $start = $null
        try { $path = $_.Path } catch { }
        try { $start = $_.StartTime } catch { }
        [pscustomobject]@{ ProcessId = $_.Id; Name = $_.ProcessName; ExecutablePath = $path; CreationDate = $start }
    })
}

Step-Phase "processes ($(@($procs).Count))"
# Services by hosting process ID. A stopped service has ProcessId 0 and is not running anywhere.
$svcByProcessId = @{}
try {
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object ProcessId, Name)) {
        $sp = [int]$s.ProcessId
        if ($sp -le 0 -or -not $s.Name) { continue }
        if (-not $svcByProcessId.ContainsKey($sp)) { $svcByProcessId[$sp] = New-Object System.Collections.Generic.List[string] }
        $svcByProcessId[$sp].Add("$($s.Name)")
    }
} catch {
    Write-Host "  Win32_Service unavailable ($($_.Exception.Message)); rows will list no services."
}

Step-Phase 'services'
# The 1.x JSON cache is archived and removed without being read (reading it is what exhausted memory).
if (Test-Path -LiteralPath $LegacyCacheFile) {
    try {
        Write-Host ("  Removing the old JSON cache ({0:N0} bytes) unread." -f (Get-Item -LiteralPath $LegacyCacheFile).Length)
        $null = Save-StateArchive -Path $LegacyCacheFile -ArchiveDir $CacheArchiveDir -Now (Get-Date)
        Remove-Item -LiteralPath $LegacyCacheFile -Force -ErrorAction Stop
    } catch { Write-Host "  Could not remove the old cache: $($_.Exception.Message)" }
}
$archivesGone = Remove-OldArchives -ArchiveDir $CacheArchiveDir -Days $ArchiveRetentionDays -Now (Get-Date)
if ($archivesGone -gt 0) { Write-Host "  Deleted $archivesGone archive(s) older than $ArchiveRetentionDays days." }
# Loading stops at 60% of the memory cap, leaving the rest of the run its room.
$cache = Read-IdentityCache -Path $CacheFile -MaxBytes $MaxCacheBytes -ArchiveDir $CacheArchiveDir -StopAtMB ([int]($MaxSelfMB * 0.6)) -Now (Get-Date)
Step-Phase "cache ($($cache.Count) entries)"
$packageMap = @{}
if (Test-NeedPackageMap -Paths @($procs | ForEach-Object { "$($_.ExecutablePath)" }) -IsServer $isServer) { $packageMap = Get-PackageSignerMap }
$stats = @{ Hits = 0; Misses = 0; Failures = 0; Deferred = 0 }
$identityByPath = @{}
$records = New-Object System.Collections.Generic.List[object]
Step-Phase 'packages'
$n = 0
foreach ($p in $procs) {
    $n++
    if ($n % 5 -eq 0) { Step-Phase "identities $n/$(@($procs).Count) (new $($stats.Misses), deferred $($stats.Deferred))" }
    try {
        $path = if ($p.ExecutablePath) { "$($p.ExecutablePath)" } else { $null }
        $g = $gp[[int]$p.ProcessId]
        if (-not $path -and $g) { try { if ($g.Path) { $path = "$($g.Path)" } } catch { } }
        $user = $null
        if ($g) { try { if ($g.UserName) { $user = "$($g.UserName)" } } catch { } }
        $id = @{ Sha256 = $null; UnhashedReason = $null }
        if ($path) {
            $pk = $path.ToLowerInvariant()
            if (-not $identityByPath.ContainsKey($pk)) {
                $identityByPath[$pk] = Get-FileIdentity -Path $path -Cache $cache -Stats $stats -Now $now -Budget $budget
            }
            $id = $identityByPath[$pk]
        }
        # After the cache, so cached entries keep the file's own Authenticode result.
        $ps = Resolve-PackageSignature -Path $path -Signer $id.Signer -Status $id.SignatureStatus -PackageMap $packageMap
        $svcs = @()
        if ($svcByProcessId.ContainsKey([int]$p.ProcessId)) { $svcs = $svcByProcessId[[int]$p.ProcessId].ToArray() }
        $records.Add(@{
            Name = "$($p.Name)"; Path = $path; User = $user; StartTime = $p.CreationDate; Services = $svcs
            Sha256 = $id.Sha256; UnhashedReason = $id.UnhashedReason
            FileVersion = $id.FileVersion; Product = $id.Product; Company = $id.Company
            Description = $id.Description; Signer = $ps.Signer; SignatureStatus = $ps.Status; SignatureSource = $ps.Source
        })
    } catch {
        # Keep the process even when something about it could not be read.
        try { $records.Add(@{ Name = "$($p.Name)"; Path = $null; User = $null; StartTime = $null; Sha256 = $null }) } catch { }
    }
}

Step-Phase "identities done (new $($stats.Misses), deferred $($stats.Deferred))"
$rows = Group-ProcessRecords -Records $records.ToArray()
Step-Phase "grouped ($(@($rows).Count) rows)"
$hostName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Environment]::MachineName }
$doc = New-InventoryDocument -Rows $rows -ProcessCount $records.Count -Hostname $hostName -CollectedAt $now
Step-Phase 'document'
$fit = Get-FittedPayload -Document $doc -MaxChars $MaxFieldChars
Step-Phase "payload (level $($fit.Level), $($fit.Value.Length) chars)"
$summary = Get-InventorySummary -Document $fit.Document -Level $fit.Level

$cacheCount = Write-IdentityCache -Cache $cache -Path $CacheFile -RetentionDays $CacheRetentionDays -Now $now

# Counts only -- the payload itself is never logged.
Write-Host ("Processes: {0} | Binaries: {1} | Unhashed: {2} | Services mapped: {3} | Cache hit/miss/fail/deferred: {4}/{5}/{6}/{7} | Cache entries: {8} | Server: {9} | Peak MB: {10:N0}" -f `
    $records.Count, $doc.binaryCount, $doc.unhashedCount, $svcByProcessId.Count, $stats.Hits, $stats.Misses, $stats.Failures, $stats.Deferred, $cacheCount, $isServer,
    ([System.Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64 / 1MB))
Write-Host "Summary: $summary"
Write-Host ("Encoded: {0} chars (limit {1}) | Trim level: {2}{3}" -f $fit.Value.Length, $MaxFieldChars, $fit.Level,
    $(if ($fit.Level -gt 0) { " (fields dropped: $($fit.Document.trimmedFields -join ', '); rows dropped: $($fit.Document.droppedRows))" } else { '' }))

# ============================================================
# PUBLISH
# ============================================================
# Liveness every run (small); the payload, its size and the summary only when the content changed or the
# 24-hour refresh is due. The publish state is saved only after the payload write succeeded on the agent.
$null = Set-NinjaField -Name $FieldProcessInventoryCollectedAt -Value (ConvertTo-IsoUtc $now)
$contentHash = Get-ContentHash -Document $doc
$publishState = $null
try { if (Test-Path -LiteralPath $PublishStateFile) { $publishState = Get-Content -LiteralPath $PublishStateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } } catch { $publishState = $null }
$okPayload = $false
if (Test-ShouldPublish -State $publishState -Hash $contentHash -Now $now -MaxAgeHours $FullRefreshHours) {
    $okPayload = Set-NinjaFieldPiped -Name $FieldProcessInventory -Value $fit.Value
    $null = Set-NinjaField -Name $FieldProcessInventoryBytes -Value ([string]$fit.Value.Length)
    $null = Set-NinjaField -Name $FieldProcessInventorySummary -Value $summary
    # Last, and only after the payload landed: a receiver that sees this hash change downloads the payload, so the
    # hash must never get ahead of it. Compared instead of a field timestamp, which NinjaOne may not move on a rewrite.
    if ($okPayload) { $null = Set-NinjaField -Name $FieldProcessInventoryHash -Value $contentHash }
} else {
    Write-Host "  Content unchanged since $($publishState.publishedAt); payload not rewritten (refresh every $FullRefreshHours h)."
}

# The change flag: up for one run after new content lands, then cleared so the condition resets.
$flagAction = Get-ChangeFlagAction -State $publishState -Hash $contentHash -Published $okPayload
$flagSet = [bool]($publishState -and $publishState.flagSet)
switch ($flagAction) {
    'set'   { if (Set-NinjaField -Name $FieldProcessInventoryChanged -Value ("CHANGED " + (ConvertTo-IsoUtc $now))) { $flagSet = $true } }
    'clear' { if (Set-NinjaField -Name $FieldProcessInventoryChanged -Value '') { $flagSet = $false } }
}

# Saved after a publish, or when the flag moved, so the next run knows both.
if ($okPayload -or $flagAction -ne 'none') {
    try {
        if (-not (Test-Path -LiteralPath $DtcStateDir)) { New-Item -ItemType Directory -Path $DtcStateDir -Force | Out-Null }
        $hashOut = if ($okPayload) { $contentHash } else { "$($publishState.hash)" }
        $atOut   = if ($okPayload) { ConvertTo-IsoUtc $now } else { "$($publishState.publishedAt)" }
        $json = [ordered]@{ hash = $hashOut; publishedAt = $atOut; flagSet = $flagSet } | ConvertTo-Json -Compress
        [System.IO.File]::WriteAllText($PublishStateFile, $json, (New-Object System.Text.UTF8Encoding($false)))
    } catch { Write-Warning "  Could not save publish state: $($_.Exception.Message)" }
}

if ($mutex) { try { $mutex.ReleaseMutex() } catch { }; try { $mutex.Dispose() } catch { } }
if ($TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
exit 0
