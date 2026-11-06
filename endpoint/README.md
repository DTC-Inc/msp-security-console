# Endpoint scripts

These are the scripts an installing MSP deploys to its own devices so the console can see what is running on them. They are optional: without them the console still has NinjaOne's installed-software inventory, and the running-processes source is off.

## process-inventory (Windows, NinjaOne)

`process/inventory/process-inventory.ps1` takes a snapshot of every running process and publishes it, one row per distinct binary (keyed by SHA-256, with signer, version, paths, users and the services it hosts), to hidden NinjaOne custom fields. The console reads those fields through the NinjaOne API. The header of the script is the full reference: the payload's JSON shape, the trim ladder, and the receiver contract.

**What it doesn't do:** it never collects command lines, which carry passwords and tokens, and there is no switch to turn that on. It changes nothing on the device beyond its own state files.

### Deploy it

1. **Create the custom fields** in NinjaOne (Administration > Devices > Global Custom Fields), each scoped to Device, with Automations set to Read/Write:

   | Name | Type | Technician permission |
   |---|---|---|
   | `processInventory` | WYSIWYG | None |
   | `processInventoryBytes` | Integer | None |
   | `processInventorySummary` | Text | Read only |
   | `processInventoryCollectedAt` | Text | None |
   | `processInventoryHash` | Text | None |
   | `processInventoryChanged` | Text | None |

   The names are set in the script's STATIC CONFIG block. If yours differ, change them there; the processes connector will take the same names as settings.
2. **Add the script** to NinjaOne's library: PowerShell, Windows, run as System, no parameters.
3. **Schedule it** in the Windows policies you want covered, **every 30 minutes**. Each run writes `processInventoryCollectedAt`, as a liveness signal. The payload itself is rewritten only when the content changes, or every 24 hours.
4. **Optional:** add a custom-field condition on `processInventoryChanged` with "contains CHANGED" and auto-reset. Its webhook tells the console which device to sync now, rather than waiting for the next poll.

### What it costs a device

It is built to stay in the background. A server VM ran out of memory under an earlier version, which is why version 1.3 added these guards:
- one instance at a time, Below Normal priority, and it skips the run when free memory is under 20% or 1 GB;
- a ceiling on its own memory (400 MB), checked after every phase: past it, the run stops without publishing;
- at most 40 new hash and signature checks per run, within 120 s; the rest are done on later runs;
- its cache (path, size and time to hash, signature and version) may grow to 100 MB, and loading stops at 240 MB of its own memory.

The first run on a busy server is the slow one, because every binary is hashed once. After that, runs re-hash only what changed.

### On the device

Everything lives under `%ProgramData%\DTC\RMM\state\` by default. Change `$DtcRmmRoot` in the STATIC CONFIG block to use your own:
- `process-inventory-cache.tsv`: the identity cache. Entries not seen for 30 days are pruned.
- `process-inventory-archive\*.zip`: any cache the script set aside (over 100 MB, too big to load, or the 1.x JSON format) is zipped here first. Zips older than 30 days are deleted. A 551 KB cache compresses to about 27 KB.
- `process-inventory-published.json`: the last published content hash, so unchanged content isn't rewritten.

### Test it

No Windows needed:

    pwsh -NoProfile -File endpoint/process/scripts/test-process-inventory.ps1

CI runs this on every PR. The test file's header covers running it in a container on an Apple-silicon Mac.

### Where it comes from

This is version **1.3.3** of the script. A change bumps the version in the script's header and passes the tests above before it ships.
