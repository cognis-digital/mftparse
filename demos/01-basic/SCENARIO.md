# Demo 01 — Basic timestomp & masquerade triage

This demo runs MFTPARSE against a small NTFS `$MFT` CSV export
(`sample_mft.csv`) that mixes benign system files with several malicious
artifacts left by an intrusion. It demonstrates every detection the engine
ships with.

## The artifacts

The CSV uses MFTECmd-style columns: `EntryNumber, FileName, ParentPath,
Extension, FileSize, IsDirectory, Created0x10 ... LastRecordChange0x30`.
The `0x10` columns are `$STANDARD_INFORMATION` (SI) timestamps — the ones the
`SetFileTime` API (and most timestomp tools) can rewrite. The `0x30` columns
are `$FILE_NAME` (FN) timestamps, set by the kernel and far harder to forge.

Planted evidence:

| File | What's wrong |
|------|--------------|
| `svch0st.exe` | SI created backdated to 2009 while FN created is 2024 (`timestomp_si_before_fn`) and SI sub-seconds zeroed while FN keeps them (`timestomp_zeroed_subsecond`). |
| `update.exe` | Dropped in `\Windows\Temp\` (`executable_in_suspicious_dir`). |
| `Invoice_2024.pdf.exe` | Double extension hiding an EXE as a PDF (`double_extension_masquerade`). |
| `payload.ps1` | Lives in `$Recycle.Bin` (`executable_in_suspicious_dir`). |
| `report.doc` (RTLO) | Filename carries a right-to-left override character (`rtlo_filename`). |

Legitimate files (`kernel32.dll`, `notepad.exe`, the `Windows` directory) are
present as controls and produce no findings.

## Run it

```sh
# Human-readable table (exits 1 because findings exist)
python -m mftparse analyze demos/01-basic/sample_mft.csv

# Machine-readable for pipelines
python -m mftparse analyze demos/01-basic/sample_mft.csv --format json

# Shareable self-contained HTML report
python -m mftparse analyze demos/01-basic/sample_mft.csv \
    --format html -o report.html
```

## Expected

Six findings across critical/high/medium severities; exit code `1`.
The control files generate nothing.
