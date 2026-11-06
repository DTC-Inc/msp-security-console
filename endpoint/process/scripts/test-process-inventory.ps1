## Unit tests for endpoint/process/inventory/process-inventory.ps1
## No Windows, no agent required. Loads only the STATIC CONFIG + helpers + pure logic (everything
## above the LOGGING marker), so nothing is collected and no field is written.
##   pwsh -NoProfile -File endpoint/process/scripts/test-process-inventory.ps1
##   podman run --rm -v "$PWD:/repo:z" mcr.microsoft.com/powershell:7.5-ubuntu-24.04 \
##     pwsh -NoProfile -c '. /repo/endpoint/process/scripts/test-process-inventory.ps1; exit $LASTEXITCODE'
##
## On an Apple-silicon Mac use an ARM64 tag (7.5-azurelinux-3.0-arm64): the ubuntu tag is x86 only,
## and .NET aborts under the Mac's x86 emulation before the first test ("qemu: uncaught target
## signal 6") -- nothing runs, so nothing passes. On ARM64 the .NET 9 runtime itself intermittently
## dies with exit 132 inside GZipStream on the ~190K-char payload in the trim section, about one run
## in five on both the azurelinux and mariner tags (seen 2026-10-26). Rerun. A crashed run can never
## read as green: it exits 132 and never reaches the assertion count below. The endpoints run
## Windows PowerShell 5.1 on .NET Framework, a different compression implementation.

$script:pass=0; $script:fail=0; $script:ran=0
function Assert-Eq { param($Expected,$Actual,[string]$Name)
  $script:ran++
  if ("$Expected" -eq "$Actual") { $script:pass++; Write-Host ("  PASS  {0}" -f $Name) }
  else { $script:fail++; Write-Host ("  FAIL  {0}  expected '{1}' got '{2}'" -f $Name,$Expected,$Actual) }
}

$Target = if ($env:PROCESS_INVENTORY_PATH) { $env:PROCESS_INVENTORY_PATH }
          else { Join-Path (Split-Path -Parent $PSScriptRoot) 'inventory/process-inventory.ps1' }
if (-not (Test-Path $Target)) { Write-Host "HARNESS ERROR: cannot find $Target"; exit 2 }
Write-Host "target: $Target"
$Scratch = Join-Path ([IO.Path]::GetTempPath()) ("procinv-test-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Scratch -Force | Out-Null
if (-not $env:ProgramData) { $env:ProgramData = $Scratch }

$src=Get-Content $Target -Raw
$a=$src.IndexOf('# STATIC CONFIG'); $b=$src.IndexOf('# LOGGING')
if ($a -lt 0 -or $b -le $a) { Write-Host "HARNESS ERROR: could not slice config+logic"; exit 2 }
Invoke-Expression $src.Substring($a,$b-$a)
foreach ($fn in @('Get-ProcessKey','Group-ProcessRecords','New-InventoryDocument','ConvertTo-CompressedBase64',
                  'ConvertFrom-CompressedBase64','Get-FittedPayload','Get-InventorySummary',
                  'Read-IdentityCache','Write-IdentityCache','Get-FileIdentity','Resolve-PackageSignature','ConvertTo-PackageSignerMap','Get-ContentHash','Test-ShouldPublish','Get-ChangeFlagAction','Test-MemoryHeadroom','Test-NeedPackageMap','Test-OverSelfCap','Get-SelfMB','Save-StateArchive','Remove-OldArchives')) {
  if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { Write-Host "HARNESS ERROR: $fn missing"; exit 2 }
}
Write-Host "config + logic loaded (fields: $FieldProcessInventory, $FieldProcessInventoryBytes, $FieldProcessInventorySummary; limit $MaxFieldChars)"

$H1 = ('a' * 64); $H2 = ('B' * 64)
function P { param($Name,$Path,$User,$Start,$Sha,$Sig='Valid',$Desc='d',$Reason=$null,$Svc=@())
  @{ Name=$Name; Path=$Path; User=$User; StartTime=$Start; Sha256=$Sha; SignatureStatus=$Sig; Signer='Acme'
     FileVersion='1.0'; Product='P'; Company='C'; Description=$Desc; UnhashedReason=$Reason; Services=$Svc } }

Write-Host "=== grouping: one row per distinct binary (SHA-256) ==="
$recs = @(
  (P 'chrome.exe' 'C:\Chrome\chrome.exe' 'EXAMPLE\a' '2026-10-22T10:00:00Z' $H1)
  (P 'chrome.exe' 'C:\Chrome\chrome.exe' 'EXAMPLE\a' '2026-10-22T09:00:00Z' $H1)
  (P 'chrome.exe' 'c:\chrome\CHROME.EXE' 'example\A' '2026-10-22T11:00:00Z' $H1)
  (P 'copy.exe'   'C:\Users\a\AppData\Local\Temp\copy.exe' 'EXAMPLE\b' '2026-10-22T12:00:00Z' $H1)
  (P 'other.exe'  'C:\Other\other.exe' 'NT AUTHORITY\SYSTEM' '2026-10-22T08:00:00Z' $H2)
)
$rows = Group-ProcessRecords -Records $recs
Assert-Eq 2 @($rows).Count 'five processes, two binaries -> two rows'
$r1 = @($rows | Where-Object { $_.sha256 -eq $H1 })[0]
Assert-Eq "sha256:$H1" $r1.key                     'key is sha256:<hex>'
Assert-Eq 4 $r1.count                              'same hash at two paths -> count 4'
Assert-Eq 2 @($r1.paths).Count                     'paths deduped case-insensitively, odd path kept'
Assert-Eq 2 $r1.pathCount                          'pathCount matches'
Assert-Eq 2 @($r1.users).Count                     'users deduped case-insensitively'
Assert-Eq '2026-10-22T09:00:00Z' $r1.firstStart    'firstStart is the earliest instance, UTC'
Assert-Eq $false $r1.unhashed                      'hashed row is not unhashed'
Assert-Eq $true $r1.signatureValid                 'Valid signature -> signatureValid'
$r2 = @($rows | Where-Object { $_.sha256 -eq $H2.ToLowerInvariant() })[0]
Assert-Eq "sha256:$($H2.ToLowerInvariant())" $r2.key 'hash normalised to lowercase'
Assert-Eq 1 @($r2.paths).Count                     'single path stays an array of one'
Assert-Eq 0 @($r1.services).Count                  'no services hosted -> empty services list'

Write-Host "=== services: Win32_Service names aggregated per binary ==="
$recsS = @(
  (P 'svchost.exe' 'C:\Windows\System32\svchost.exe' 'NT AUTHORITY\SYSTEM' $null $H1 'Valid' 'd' $null @('Dnscache','LanmanWorkstation'))
  (P 'svchost.exe' 'C:\Windows\System32\svchost.exe' 'NT AUTHORITY\LOCAL SERVICE' $null $H1 'Valid' 'd' $null @('dnscache','W32Time'))
  (P 'svchost.exe' 'C:\Windows\System32\svchost.exe' 'NT AUTHORITY\SYSTEM' $null $H1 'Valid' 'd' $null @())
  (P 'agent.exe'   'C:\Agent\agent.exe' 'NT AUTHORITY\SYSTEM' $null $H2 'Valid' 'd' $null @('AgentSvc'))
)
$rowsS = Group-ProcessRecords -Records $recsS
$svc = @($rowsS | Where-Object { $_.name -eq 'svchost.exe' })[0]
Assert-Eq 3 $svc.count                                  'three svchost instances, one row'
Assert-Eq 'Dnscache,LanmanWorkstation,W32Time' (@($svc.services) -join ',') 'services deduped case-insensitively, sorted'
$ag = @($rowsS | Where-Object { $_.name -eq 'agent.exe' })[0]
Assert-Eq 1 @($ag.services).Count                       'single service stays an array of one'
$jsonS = ConvertTo-PayloadJson (New-InventoryDocument -Rows $rowsS -ProcessCount 4 -Hostname 'S' -CollectedAt (Get-Date))
$backS = $jsonS | ConvertFrom-Json
Assert-Eq 1 @(@($backS.binaries | Where-Object { $_.name -eq 'agent.exe' })[0].services).Count 'one-element services still an array after JSON'

Write-Host "=== counts and the summary line ==="
$recsC = @(
  (P 'a.exe' 'C:\a.exe' 'U' $null ('1' * 64) 'Valid')
  (P 'b.exe' 'C:\b.exe' 'U' $null ('2' * 64) 'NotSigned')
  (P 'c.exe' 'C:\c.exe' 'U' $null ('3' * 64) 'NotSigned')
  (P 'd.exe' 'C:\d.exe' 'U' $null ('4' * 64) 'HashMismatch')
  (P 'e.exe' 'C:\e.exe' 'U' $null ('5' * 64) 'Unavailable')
  (P 'System' $null $null $null $null)
)
$docC = New-InventoryDocument -Rows (Group-ProcessRecords -Records $recsC) -ProcessCount 9 -Hostname 'C' -CollectedAt ([datetime]::new(2026,10,26,14,5,9,[DateTimeKind]::Utc))
Assert-Eq 2 $docC.unsignedCount          'unsignedCount counts NotSigned only'
Assert-Eq 1 $docC.invalidSignatureCount  'invalidSignatureCount counts signed-but-not-Valid, not Unavailable'
Assert-Eq 1 $docC.unhashedCount          'unhashedCount unchanged'
$sumC = Get-InventorySummary -Document $docC -Level 0
Assert-Eq '9 procs, 6 binaries | unsigned 2, invalid sig 1, unhashed 1' $sumC 'summary line, untrimmed, no timestamp (it is processInventoryCollectedAt)'
Assert-Eq $true ((Get-InventorySummary -Document $docC -Level 3).EndsWith(' | trimmed L3')) 'summary names the trim level'
Assert-Eq $true ((Get-InventorySummary -Document $docC -Level 0 -MaxLength 20).Length -le 20) 'summary never exceeds its cap'
Assert-Eq $true ($sumC.Length -lt 190)   'summary under the 190-char text-field budget'

Write-Host "=== unhashed fallback: kept, keyed by path or name, flagged ==="
$recs2 = @(
  (P 'System' $null $null $null $null)
  (P 'System' $null $null $null $null)
  (P 'Registry' $null $null $null $null)
  (P 'MsMpEng.exe' 'C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe' 'NT AUTHORITY\SYSTEM' $null $null 'Valid' 'd' 'unreadable')
)
$rows2 = Group-ProcessRecords -Records $recs2
Assert-Eq 3 @($rows2).Count 'no process dropped: System, Registry, MsMpEng'
$sys = @($rows2 | Where-Object { $_.key -eq 'name:system' })[0]
Assert-Eq $true $sys.unhashed           'no-file process flagged unhashed'
Assert-Eq 'no-path' $sys.unhashedReason 'reason no-path'
Assert-Eq 2 $sys.count                  'pseudo-process instances still counted'
Assert-Eq $null $sys.signatureStatus    'no signature claimed for an unhashed row'
$mp = @($rows2 | Where-Object { $_.key -like 'path:*' })[0]
Assert-Eq 'path:c:\programdata\microsoft\windows defender\msmpeng.exe' $mp.key 'unreadable file keyed by lowercase path'
Assert-Eq 'unreadable' $mp.unhashedReason 'reason unreadable'
Assert-Eq $false $mp.signatureValid      'unhashed row never signatureValid'
$doc2 = New-InventoryDocument -Rows $rows2 -ProcessCount 4 -Hostname 'T' -CollectedAt ([datetime]'2026-10-22T12:00:00Z')
Assert-Eq 3 $doc2.unhashedCount         'document counts unhashed rows'

Write-Host "=== encode round-trip: base64 -> gunzip -> JSON equals input ==="
$doc = New-InventoryDocument -Rows $rows -ProcessCount 5 -Hostname 'WS-0042' -CollectedAt ([datetime]::new(2026,10,22,14,0,5,[DateTimeKind]::Utc))
$json = ConvertTo-PayloadJson $doc
$b64 = ConvertTo-CompressedBase64 $json
Assert-Eq $true ($b64 -match '^[A-Za-z0-9+/]+=*$')            'output is pure base64 (no HTML specials)'
Assert-Eq $json (ConvertFrom-CompressedBase64 $b64)            'decoded text is byte-identical to the JSON'
Assert-Eq $json (ConvertFrom-CompressedBase64 ("<p>" + $b64.Substring(0,10) + "`n" + $b64.Substring(10) + "</p>")) 'receiver strips WYSIWYG tags/whitespace'
$back = (ConvertFrom-CompressedBase64 $b64) | ConvertFrom-Json
Assert-Eq 1 $back.schema                      'schema version present'
# Checked on the raw text: PS 7's ConvertFrom-Json would turn the string into a local DateTime.
Assert-Eq $true ((ConvertFrom-CompressedBase64 $b64) -match '"collectedAt":"2026-10-22T14:00:05Z"') 'collectedAt is ISO UTC in the JSON'
Assert-Eq 'WS-0042' $back.hostname            'hostname present'
Assert-Eq $false $back.trimmed                'trimmed marker present and false'
Assert-Eq 2 @($back.binaries).Count           'binaries survive the round trip'
Assert-Eq 1 @(@($back.binaries | Where-Object { $_.sha256 -eq $H2.ToLowerInvariant() })[0].paths).Count 'one-element paths still an array after JSON'
$fit0 = Get-FittedPayload -Document $doc -MaxChars 190000
Assert-Eq 0 $fit0.Level                        'small payload is not trimmed'
Assert-Eq $b64 $fit0.Value                     'untrimmed value equals the plain encoding'

Write-Host "=== trimming ladder: descriptions, then start times, never cut base64 ==="
# Build a big, poorly-compressible document: 400 binaries with random descriptions and paths.
$rng = [Random]::new(7)
function RandStr { param($n) -join (1..$n | ForEach-Object { [char]($rng.Next(33,126)) }) }
function BigRecs { param([int]$n,[int]$unsigned)
  $rs = @()
  for ($i=0; $i -lt $n; $i++) {
    $h = -join (1..64 | ForEach-Object { '{0:x}' -f $rng.Next(0,16) })
    $sig = if ($i -lt $unsigned) { 'NotSigned' } else { 'Valid' }
    $rs += (P "p$i.exe" ("C:\x\" + (RandStr 40) + ".exe") ("U\" + (RandStr 10)) ([datetime]'2026-10-22T08:00:00Z').AddSeconds($rng.Next(0,80000)) $h $sig (RandStr 120))
    $rs += (P "p$i.exe" ("C:\y\" + (RandStr 40) + ".exe") ("U\" + (RandStr 10)) $null $h $sig 'x')
  }
  ,$rs }
$bigRecs = BigRecs 400 20   # built once; each fit groups them afresh, so every rung sees identical content
$bigRows = Group-ProcessRecords -Records $bigRecs
# A fixed collectedAt: with Get-Date here, a second ticking over between two builds changes the
# compressed length, and "just over the limit" can land on level 0. Seen 2026-10-26 under a mutant run.
$BigAt = [datetime]::new(2026,10,22,14,0,0,[DateTimeKind]::Utc)
$full = ConvertTo-CompressedBase64 (ConvertTo-PayloadJson (New-InventoryDocument -Rows $bigRows -ProcessCount 800 -Hostname 'BIG' -CollectedAt $BigAt))
Write-Host "  full encoded size: $($full.Length) chars"
function Fit-At { param($limit) $d = New-InventoryDocument -Rows (Group-ProcessRecords -Records $bigRecs) -ProcessCount 800 -Hostname 'BIG' -CollectedAt $BigAt; Get-FittedPayload -Document $d -MaxChars $limit }
$lim1 = [int]($full.Length - 1)
$f1 = Fit-At $lim1
Assert-Eq 1 $f1.Level                           'just over the limit -> level 1 (description dropped)'
Assert-Eq $true ($f1.Value.Length -le $lim1)    'level 1 value fits'
$d1 = (ConvertFrom-CompressedBase64 $f1.Value) | ConvertFrom-Json
Assert-Eq $true $d1.trimmed                     'trimmed marker set'
Assert-Eq 'description' ($d1.trimmedFields -join ',') 'trimmedFields names description'
Assert-Eq $false ($d1.binaries[0].PSObject.Properties.Name -contains 'description') 'description gone from rows'
Assert-Eq $true  ($d1.binaries[0].PSObject.Properties.Name -contains 'firstStart')  'firstStart still present at level 1'
Assert-Eq 400 @($d1.binaries).Count             'no rows dropped at level 1'
# Find the size after level 1 and 2 to force exact rungs.
$l1len = $f1.Value.Length
$f2 = Fit-At ($l1len - 1)
Assert-Eq 2 $f2.Level                           'below level-1 size -> level 2 (start times dropped)'
$d2 = (ConvertFrom-CompressedBase64 $f2.Value) | ConvertFrom-Json
Assert-Eq 'description,firstStart' ($d2.trimmedFields -join ',') 'ladder order: description then firstStart'
Assert-Eq $true ($f2.Value.Length -le ($l1len - 1)) 'level 2 value fits'
# Level 6: keep only rows that are not validly signed.
$f6 = Fit-At 9000
$d6 = (ConvertFrom-CompressedBase64 $f6.Value) | ConvertFrom-Json
Write-Host "  9000-char limit -> level $($f6.Level), $(@($d6.binaries).Count) rows, $($f6.Value.Length) chars"
Assert-Eq 6 $f6.Level                           'tight limit -> level 6'
Assert-Eq 'description,firstStart,users,services,paths' ($d6.trimmedFields -join ',') 'ladder order through level 5: services before paths'
Assert-Eq 20 @($d6.binaries).Count              'level 6 keeps exactly the 20 unsigned rows'
Assert-Eq 380 $d6.droppedRows                   'droppedRows counts the 380 signed rows'
Assert-Eq 0 @($d6.binaries | Where-Object { $_.signatureValid }).Count 'no validly signed row survives level 6'
Assert-Eq 400 $d6.binaryCount                   'binaryCount still reports the full total'
Assert-Eq 20 $d6.unsignedCount                  'unsignedCount describes the whole snapshot after trimming'
$f7 = Fit-At 600
$d7 = (ConvertFrom-CompressedBase64 $f7.Value) | ConvertFrom-Json
Assert-Eq 7 $f7.Level                           'absurd limit -> level 7 overflow'
Assert-Eq 0 @($d7.binaries).Count               'overflow carries no rows'
Assert-Eq 400 $d7.droppedRows                   'overflow says every row was dropped'
foreach ($f in @($f1,$f2,$f6,$f7)) { Assert-Eq $true ($f.Value -match '^[A-Za-z0-9+/]+=*$') "level $($f.Level) value is complete base64 (decodes above)" }

Write-Host "=== MSIX packages: Store apps are signed by their package, not the file ==="
$pkgMap = ConvertTo-PackageSignerMap -Packages @(
  [pscustomobject]@{ InstallLocation='C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm'; Publisher='CN=24803D75-212C-471A-BC57-9EF86AB91435'; SignatureKind='Store' }
  [pscustomobject]@{ InstallLocation='C:\Program Files\WindowsApps\Microsoft.WidgetsPlatformRuntime_1.6.19.0_x64__8wekyb3d8bbwe\'; Publisher='CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'; SignatureKind='System' }
  [pscustomobject]@{ InstallLocation='C:\Program Files\WindowsApps\Contoso.Sideload_1.0.0.0_x64__abc'; Publisher='CN=Contoso Dev'; SignatureKind='Developer' }
  [pscustomobject]@{ InstallLocation=$null; Publisher='CN=Broken'; SignatureKind='Store' }
)
Assert-Eq 3 $pkgMap.Count 'package map skips a package with no install location'
$wa = Resolve-PackageSignature -Path 'C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe' -Signer $null -Status 'NotSigned' -PackageMap $pkgMap
Assert-Eq 'Valid' $wa.Status                       'Store package file NotSigned -> Valid'
Assert-Eq 'package' $wa.Source                     '... signatureSource package'
Assert-Eq '24803D75-212C-471A-BC57-9EF86AB91435' $wa.Signer '... signer is the package publisher CN'
$wd = Resolve-PackageSignature -Path 'c:\program files\windowsapps\microsoft.widgetsplatformruntime_1.6.19.0_x64__8wekyb3d8bbwe\WidgetService.exe' -Signer $null -Status 'NotSigned' -PackageMap $pkgMap
Assert-Eq 'Valid' $wd.Status                       'System package matched case-insensitively'
Assert-Eq 'Microsoft Corporation' $wd.Signer      '... publisher CN parsed out of the full DN'
$dv = Resolve-PackageSignature -Path 'C:\Program Files\WindowsApps\Contoso.Sideload_1.0.0.0_x64__abc\app.exe' -Signer $null -Status 'NotSigned' -PackageMap $pkgMap
Assert-Eq 'NotSigned' $dv.Status                   'Developer (sideloaded) package stays NotSigned'
$df = Resolve-PackageSignature -Path 'C:\Program Files\Deskflow\deskflow-daemon.exe' -Signer $null -Status 'NotSigned' -PackageMap $pkgMap
Assert-Eq 'NotSigned' $df.Status                   'plain unsigned file outside any package stays NotSigned'
Assert-Eq 'file' $df.Source                        '... signatureSource file'
$pf = Resolve-PackageSignature -Path 'C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgmEVIL\x.exe' -Signer $null -Status 'NotSigned' -PackageMap $pkgMap
Assert-Eq 'NotSigned' $pf.Status                   'a sibling folder sharing the prefix does not match'
$fv = Resolve-PackageSignature -Path 'C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\signed.exe' -Signer 'Meta' -Status 'Valid' -PackageMap $pkgMap
Assert-Eq 'file' $fv.Source                        'a file with its own valid signature keeps it'
$bad = Resolve-PackageSignature -Path 'C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\tampered.exe' -Signer 'X' -Status 'HashMismatch' -PackageMap $pkgMap
Assert-Eq 'HashMismatch' $bad.Status               'a broken file signature is never upgraded by its package'
$empty = Resolve-PackageSignature -Path 'C:\x.exe' -Signer $null -Status 'NotSigned' -PackageMap @{}
Assert-Eq 'NotSigned' $empty.Status                'empty map (Appx unavailable) changes nothing'
$rowsP = Group-ProcessRecords -Records @(
  (@{ Name='WhatsApp.Root.exe'; Path='C:\WA\w.exe'; Sha256=$H1; SignatureStatus='Valid'; Signer='24803D75'; SignatureSource='package' })
  (@{ Name='other.exe'; Path='C:\O\o.exe'; Sha256=$H2; SignatureStatus='Valid'; Signer='Acme' })
)
Assert-Eq 'package' (@($rowsP | Where-Object { $_.sha256 -eq $H1 })[0].signatureSource) 'row carries signatureSource package'
Assert-Eq 'file' (@($rowsP | Where-Object { $_.sha256 -eq $H2.ToLowerInvariant() })[0].signatureSource) 'row defaults signatureSource file'

Write-Host "=== publish only on change: content hash and the 24-hour refresh ==="
function B { param($Key,$Ver='1.0',$Sig='Valid',$Signer='Acme',$Paths=@('C:\a.exe'),$Svc=@(),$Count=1,$Users=@('EXAMPLE\a'),$First='2026-10-26T08:00:00Z')
  [ordered]@{ key=$Key; fileVersion=$Ver; signatureStatus=$Sig; signer=$Signer; signatureSource='file'; paths=$Paths; services=$Svc; count=$Count; users=$Users; firstStart=$First } }
$d1 = @{ collectedAt='2026-10-26T10:00:00Z'; processCount=40; binaries=@((B 'sha256:aa'), (B 'sha256:bb' -Svc @('Spooler'))) }
$h1 = Get-ContentHash -Document $d1
Assert-Eq 64 $h1.Length 'content hash is a SHA-256 hex string'
$d2 = @{ collectedAt='2026-10-26T10:30:00Z'; processCount=52; binaries=@((B 'sha256:bb' -Svc @('Spooler') -Count 9 -Users @('EXAMPLE\b') -First '2026-10-26T10:29:00Z'), (B 'sha256:aa')) }
Assert-Eq $h1 (Get-ContentHash -Document $d2) 'same binaries: collectedAt, process count, instance counts, users, start times and order do not change the hash'
Assert-Eq $false ($h1 -eq (Get-ContentHash -Document @{ binaries=@((B 'sha256:aa' -Ver '1.1'), (B 'sha256:bb' -Svc @('Spooler'))) })) 'a version change changes the hash'
Assert-Eq $false ($h1 -eq (Get-ContentHash -Document @{ binaries=@((B 'sha256:aa'), (B 'sha256:bb' -Svc @('Spooler')), (B 'sha256:cc')) })) 'a new binary changes the hash'
Assert-Eq $false ($h1 -eq (Get-ContentHash -Document @{ binaries=@((B 'sha256:aa' -Sig 'NotSigned'), (B 'sha256:bb' -Svc @('Spooler'))) })) 'a signature change changes the hash'
Assert-Eq $false ($h1 -eq (Get-ContentHash -Document @{ binaries=@((B 'sha256:aa'), (B 'sha256:bb')) })) 'a hosted service change changes the hash'
Assert-Eq $false ($h1 -eq (Get-ContentHash -Document @{ binaries=@((B 'sha256:aa' -Paths @('C:\Temp\a.exe')), (B 'sha256:bb' -Svc @('Spooler'))) })) 'a new path changes the hash'
$now = [datetime]::Parse('2026-10-26T12:00:00Z').ToUniversalTime()
Assert-Eq $true  (Test-ShouldPublish -State $null -Hash $h1 -Now $now) 'no previous publish -> publish'
Assert-Eq $false (Test-ShouldPublish -State @{ hash=$h1; publishedAt='2026-10-26T06:00:00Z' } -Hash $h1 -Now $now) 'same hash within 24h -> skip'
Assert-Eq $true  (Test-ShouldPublish -State @{ hash='x'; publishedAt='2026-10-26T11:59:00Z' } -Hash $h1 -Now $now) 'hash changed -> publish'
Assert-Eq $true  (Test-ShouldPublish -State @{ hash=$h1; publishedAt='2026-10-25T11:00:00Z' } -Hash $h1 -Now $now) 'same hash older than 24h -> publish (keeps the datalake retention fed)'
Assert-Eq $true  (Test-ShouldPublish -State @{ hash=$h1; publishedAt='not a date' } -Hash $h1 -Now $now) 'unreadable state -> publish'

Write-Host "=== change flag: set on a content change, cleared on the next run ==="
Assert-Eq 'set'   (Get-ChangeFlagAction -State $null -Hash 'h1' -Published $true) 'first publish on a device sets the flag'
Assert-Eq 'set'   (Get-ChangeFlagAction -State @{ hash='h0'; flagSet=$false } -Hash 'h1' -Published $true) 'a changed hash that published sets the flag'
Assert-Eq 'none'  (Get-ChangeFlagAction -State @{ hash='h1'; flagSet=$false } -Hash 'h1' -Published $true) 'the 24-hour refresh of the same content does not set it'
Assert-Eq 'clear' (Get-ChangeFlagAction -State @{ hash='h1'; flagSet=$true } -Hash 'h1' -Published $false) 'the next quiet run clears a set flag'
Assert-Eq 'clear' (Get-ChangeFlagAction -State @{ hash='h1'; flagSet=$true } -Hash 'h1' -Published $true) 'a refresh right after a change still clears it'
Assert-Eq 'none'  (Get-ChangeFlagAction -State @{ hash='h1'; flagSet=$false } -Hash 'h1' -Published $false) 'a quiet run with no flag writes nothing'
Assert-Eq 'none'  (Get-ChangeFlagAction -State @{ hash='h0'; flagSet=$false } -Hash 'h1' -Published $false) 'a change whose payload failed to publish does not set it'
Assert-Eq 'set'   (Get-ChangeFlagAction -State @{ hash='h0'; flagSet=$true } -Hash 'h1' -Published $true) 'a second change while the flag is up sets it again (new time)'

Write-Host "=== cache: path + size + LastWriteTime ==="
$bin = Join-Path $Scratch 'tool.exe'
[IO.File]::WriteAllBytes($bin, [byte[]](1..200))
$expected = (Get-FileHash -LiteralPath $bin -Algorithm SHA256).Hash.ToLowerInvariant()
$cache = @{}; $st = @{ Hits=0; Misses=0; Failures=0 }; $now = Get-Date
$id1 = Get-FileIdentity -Path $bin -Cache $cache -Stats $st -Now $now
Assert-Eq $expected $id1.Sha256      'first read hashes the file'
Assert-Eq 1 $st.Misses               'first read is a miss'
$cache[$bin.ToLowerInvariant()].sha256 = 'cachedsentinel'
$id2 = Get-FileIdentity -Path $bin -Cache $cache -Stats $st -Now $now
Assert-Eq 'cachedsentinel' $id2.Sha256 'unchanged file served from cache (proved by sentinel)'
Assert-Eq 1 $st.Hits                 'second read is a hit'
(Get-Item $bin).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddMinutes(-5)
$id3 = Get-FileIdentity -Path $bin -Cache $cache -Stats $st -Now $now
Assert-Eq $expected $id3.Sha256      'changed LastWriteTime forces a re-hash'
$cf = Join-Path $Scratch 'state/cache.tsv'
$n = Write-IdentityCache -Cache $cache -Path $cf -RetentionDays 30 -Now $now
Assert-Eq 1 $n                       'cache written with one entry'
$cache2 = Read-IdentityCache -Path $cf
Assert-Eq $expected $cache2[$bin.ToLowerInvariant()].sha256 'cache survives a write/read cycle'
$n2 = Write-IdentityCache -Cache $cache2 -Path $cf -RetentionDays 30 -Now $now.AddDays(31)
Assert-Eq 0 $n2                      'entries unseen for > retention are pruned'
Set-Content -LiteralPath $cf -Value '{ not json'
Assert-Eq 0 (Read-IdentityCache -Path $cf).Count 'corrupt cache -> empty, no throw'
$missing = Get-FileIdentity -Path (Join-Path $Scratch 'nope.exe') -Cache @{} -Stats $st -Now $now
Assert-Eq $null $missing.Sha256      'unreadable file -> no hash'
Assert-Eq 'unreadable' $missing.UnhashedReason 'unreadable file -> reason recorded'


# ---- 1.3.0 low impact: memory guard, package lookup, bounded work ----
Assert-Eq $true  (Test-MemoryHeadroom -FreeKB (8GB/1KB) -TotalKB (16GB/1KB) -MinPercent 20 -MinMB 1024) 'memory: 8 of 16 GB free -> runs'
Assert-Eq $false (Test-MemoryHeadroom -FreeKB (2GB/1KB) -TotalKB (16GB/1KB) -MinPercent 20 -MinMB 1024) 'memory: 12.5% free -> skips'
Assert-Eq $false (Test-MemoryHeadroom -FreeKB (900MB/1KB) -TotalKB (4GB/1KB) -MinPercent 20 -MinMB 1024) 'memory: under 1 GB free -> skips even at 22%'
Assert-Eq $true  (Test-MemoryHeadroom -FreeKB 0 -TotalKB 0 -MinPercent 20 -MinMB 1024) 'memory: unknown -> runs'
Assert-Eq $false (Test-NeedPackageMap -Paths @('C:\Program Files\WindowsApps\X\x.exe') -IsServer $true) 'packages: never on a server'
Assert-Eq $true  (Test-NeedPackageMap -Paths @('C:\Windows\a.exe','C:\Program Files\WindowsApps\X\x.exe') -IsServer $false) 'packages: a workstation with a Store binary'
Assert-Eq $false (Test-NeedPackageMap -Paths @('C:\Windows\a.exe', $null) -IsServer $false) 'packages: no Store binary -> no lookup'
$bf1 = Join-Path $Scratch 'b1.exe'; $bf2 = Join-Path $Scratch 'b2.exe'; Set-Content -LiteralPath $bf1 -Value 'one'; Set-Content -LiteralPath $bf2 -Value 'two'
$bst = @{ Hits = 0; Misses = 0; Failures = 0; Deferred = 0 }
$bud = @{ Left = 1; Deadline = (Get-Date).AddMinutes(5) }
$i1 = Get-FileIdentity -Path $bf1 -Cache @{} -Stats $bst -Now $now -Budget $bud
$i2 = Get-FileIdentity -Path $bf2 -Cache @{} -Stats $bst -Now $now -Budget $bud
Assert-Eq $true ([bool]$i1.Sha256) 'budget: the first new file is hashed'
Assert-Eq 'deferred' $i2.UnhashedReason 'budget: past the per-run cap the next new file is deferred'
Assert-Eq 1 $bst.Deferred 'budget: deferred counted'
$late = Get-FileIdentity -Path $bf2 -Cache @{} -Stats $bst -Now $now -Budget @{ Left = 5; Deadline = (Get-Date).AddSeconds(-1) }
Assert-Eq 'deferred' $late.UnhashedReason 'budget: past the time budget -> deferred'
$c3 = @{}; $null = Get-FileIdentity -Path $bf1 -Cache $c3 -Stats $bst -Now $now
$hit = Get-FileIdentity -Path $bf1 -Cache $c3 -Stats $bst -Now $now -Budget @{ Left = 0; Deadline = (Get-Date).AddMinutes(5) }
Assert-Eq $true ([bool]$hit.Sha256) 'budget: a cache hit costs no budget, even at 0 left'
Assert-Eq $true  (Test-OverSelfCap -MB 401 -CapMB 400) 'self cap: over 400 MB stops'
Assert-Eq $false (Test-OverSelfCap -MB 399 -CapMB 400) 'self cap: under runs'
Assert-Eq $false (Test-OverSelfCap -MB 9999 -CapMB 0) 'self cap: 0 means off'
Assert-Eq $true ((Get-SelfMB) -gt 0) 'self MB is read'
# 1.3.2: the cache is a stream of lines; an oversize file is dropped unread; values with tabs survive.
$ct = @{ 'c:\\x\\a.exe' = @{ path = 'C:\\x\\a.exe'; size = 10; mtimeTicks = 5; sha256 = ('c' * 64); signer = "Acme`tInc"; signatureStatus = 'Valid'; fileVersion = '1'; product = 'P'; company = 'C'; description = "two`nlines"; lastSeen = (ConvertTo-IsoUtc $now) } }
$cft = Join-Path $Scratch 'state/c2.tsv'
Assert-Eq 1 (Write-IdentityCache -Cache $ct -Path $cft -RetentionDays 30 -Now $now) 'tsv cache: written'
$back = Read-IdentityCache -Path $cft
Assert-Eq ('c' * 64) $back['c:\\x\\a.exe'].sha256 'tsv cache: round trip'
Assert-Eq 'Acme Inc' $back['c:\\x\\a.exe'].signer 'tsv cache: a tab in a value becomes a space, columns stay aligned'
$big = Join-Path $Scratch 'state/big.tsv'; [System.IO.File]::WriteAllText($big, ('x' * 2048))
$arc = Join-Path $Scratch 'state/archive'
Assert-Eq 0 (Read-IdentityCache -Path $big -MaxBytes 1024 -ArchiveDir $arc -Now $now).Count 'tsv cache: over the size cap -> not loaded'
Assert-Eq $false (Test-Path -LiteralPath $big) 'tsv cache: the oversize file is removed'
# 1.3.3: what is set aside is zipped first, and the zip holds the file whole.
$zips = @(Get-ChildItem -LiteralPath $arc -Filter '*.zip')
Assert-Eq 1 $zips.Count 'archive: the oversize cache was zipped'
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$zr = [System.IO.Compression.ZipFile]::OpenRead($zips[0].FullName)
$ent = @($zr.Entries); $rd = New-Object System.IO.StreamReader($ent[0].Open()); $inner = $rd.ReadToEnd(); $rd.Dispose(); $zr.Dispose()
Assert-Eq 'big.tsv' $ent[0].Name 'archive: the entry is named for the file'
Assert-Eq ('x' * 2048) $inner 'archive: the content survives'
Assert-Eq $true ($zips[0].Length -lt 2048) 'archive: compressed'
# Two archives in the same second do not collide.
[System.IO.File]::WriteAllText($big, 'y')
$z2 = Save-StateArchive -Path $big -ArchiveDir $arc -Now $now
Assert-Eq 2 @(Get-ChildItem -LiteralPath $arc -Filter '*.zip').Count 'archive: same-second archives get distinct names'
Assert-Eq $null (Save-StateArchive -Path (Join-Path $Scratch 'nope.tsv') -ArchiveDir $arc -Now $now) 'archive: a missing file archives nothing'
# Retention: older than 30 days goes, newer stays.
(Get-Item -LiteralPath $z2).LastWriteTimeUtc = $now.ToUniversalTime().AddDays(-31)
Assert-Eq 1 (Remove-OldArchives -ArchiveDir $arc -Days 30 -Now $now) 'archive: one older than 30 days deleted'
Assert-Eq 1 @(Get-ChildItem -LiteralPath $arc -Filter '*.zip').Count 'archive: the recent one is kept'
Assert-Eq 0 (Remove-OldArchives -ArchiveDir (Join-Path $Scratch 'none') -Days 30 -Now $now) 'archive: no directory, nothing to do'
# Loading stops before memory runs out: with a 1 MB ceiling it stops at the first check, archives, and keeps what it read.
$many = @{}; for ($i = 0; $i -lt 4500; $i++) { $many["c:\m\$i.exe"] = @{ path = "C:\m\$i.exe"; size = $i; mtimeTicks = 1; sha256 = ('d' * 64); signer = 'A'; signatureStatus = 'Valid'; fileVersion = '1'; product = 'P'; company = 'C'; description = 'x'; lastSeen = (ConvertTo-IsoUtc $now) } }
$cfm = Join-Path $Scratch 'state/many.tsv'
Assert-Eq 4500 (Write-IdentityCache -Cache $many -Path $cfm -RetentionDays 30 -Now $now) 'stop: 4,500-entry cache written'
$part = Read-IdentityCache -Path $cfm -ArchiveDir $arc -StopAtMB 1 -Now $now
Assert-Eq $true ($part.Count -gt 0 -and $part.Count -lt 4500) 'stop: loading stopped part-way'
Assert-Eq $false (Test-Path -LiteralPath $cfm) 'stop: the full file was set aside'
Assert-Eq 2 @(Get-ChildItem -LiteralPath $arc -Filter '*.zip').Count 'stop: and zipped'
$null = Write-IdentityCache -Cache $many -Path $cfm -RetentionDays 30 -Now $now
Assert-Eq 4500 (Read-IdentityCache -Path $cfm -Now $now).Count 'stop: without a ceiling every entry loads'
Assert-Eq 104857600 $MaxCacheBytes 'the cache may grow to 100 MB'
Assert-Eq 30 $ArchiveRetentionDays 'archives are kept 30 days'
$srcText = Get-Content $Target -Raw
Assert-Eq $false ($srcText -match 'ConvertFrom-Json' -and ($srcText -split 'function Read-IdentityCache')[1].Split([char]0x7D)[0] -match 'ConvertFrom-Json') 'the cache is never parsed with ConvertFrom-Json'
Assert-Eq $true ($srcText.IndexOf('Removing the old JSON cache') -lt $srcText.IndexOf('$cache = Read-IdentityCache')) 'the old JSON cache is removed before any cache read'
Assert-Eq $true ($srcText.IndexOf('Save-StateArchive -Path $LegacyCacheFile') -lt $srcText.IndexOf('Remove-Item -LiteralPath $LegacyCacheFile')) 'the old JSON cache is archived before it is removed'
Assert-Eq $true ($srcText -match 'machineLow' -and $srcText -match 'Stopping without publishing') 'phase check stops on machine-wide low memory too'
Assert-Eq $true (([regex]::Matches($srcText, 'Step-Phase ')).Count -ge 10) 'memory logged at every phase'
Assert-Eq $true ($srcText -match "New-Object System\.Threading\.Mutex\(\`$false, \`$MutexName\)" -and $srcText -match 'WaitOne\(0\)') 'single instance: a mutex, never waited on'
Assert-Eq $true ($srcText -match 'ProcessPriorityClass\]::BelowNormal') 'background: Below Normal priority'
Assert-Eq $true ($srcText.IndexOf('Test-MemoryHeadroom -FreeKB') -lt $srcText.IndexOf('Get-CimInstance -ClassName Win32_Process ')) 'memory guard runs before any collection'
Assert-Eq $false ($srcText -match '(?m)^\$packageMap = Get-PackageSignerMap') 'package lookup is never unconditional'

Remove-Item -Recurse -Force $Scratch -ErrorAction SilentlyContinue
Write-Host ''
Write-Host ("ASSERTIONS RUN: {0}   PASS: {1}   FAIL: {2}" -f $script:ran,$script:pass,$script:fail)
if ($script:ran -lt 140) { Write-Host "HARNESS ERROR: expected >=140 assertions, only $($script:ran) executed"; exit 2 }
if ($script:fail -gt 0) { exit 1 }
Write-Host "ALL GREEN"
