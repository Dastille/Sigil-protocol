# Roadmap

The order of planned work on Sigil. Each step is finished, with tests and measurements,
before the next one starts. The `.sg1` format changes only for a large measured gain;
new behaviour is opt-in, and every Sigil Archive made so far keeps opening.

| Step | Work | Status |
|---|---|---|
| 1 | Classic single seals stream: Inscribe, open, Mend and Scry read a window at a time instead of the whole file. | Done |
| 2 | Quick fixes: a Tome lists every path it leaves out (`--fail-on-skip` to refuse instead); `mount` reads large members one chunk star at a time; large Tome members are listed as files, not nests; a test that failed by chance now checks leaks soundly. | Done |
| 3 | Measure how fragile a Tome's folder list is: how much damage to the list loses which files. | Planned |
| 4 | Opt-in restore of whatever can be saved from a damaged Tome, with a full report of what was lost and a non-zero exit code (`sigil unseal --salvage`, exit 7). | Done |
| 5 | Opt-in: keep dotfiles and file permissions in Tomes. | Planned |
| 6 | Measure chunk sharing between versions: fixed-size chunks against content-defined chunks, and the extra repair data that shared chunks need. | Planned |
| 7 | Repair head-to-head against RAR recovery records and PAR2 on the same damage. | Planned |
| 8 | v0.9.0 release with signed checksums. | Planned |
| 9 | Signed builds for Windows and macOS. | Planned |
| 10 | Self-extracting Sigil Archive (opens without Sigil installed). | Planned |

## Names

| Name | Meaning |
|---|---|
| Sigil Archive | A `.sg1` file |
| Tome | A `.sg1` of a whole folder |
| Codex | A `name.sigil/` folder (a Vault, a Constellation or a signed log) |
| Ward | A lock (passphrase or key) |
| Channel, mana | Sending with spare pieces |
| Inscribe | Make a Sigil Archive |
| Scry | Check |
| Mend | Repair |
| Frost Rune | Cold storage |

Details of finished work are in [CHANGELOG.md](CHANGELOG.md).
