# Integrations

**mftparse** plugs into your stack through [`cognis-connect`](https://github.com/cognis-digital/cognis-connect),
the suite's integration SDK. It maps any tool's JSON into a canonical **Finding** and
forwards it to the platforms that fit the **Host / artifact forensics** domain.

```bash
pip install "git+https://github.com/cognis-digital/cognis-connect.git"
```

## Forward findings to a platform

Once `mftparse` emits JSON findings, pipe them straight to a destination — `--dry-run`
previews the exact request without sending:

```bash
mftparse ... --format json | cognis-connect emit --to stix   # STIX 2.1 bundle
mftparse ... --format json | cognis-connect emit --to misp --url $URL --token $TOK   # MISP event
mftparse ... --format json | cognis-connect emit --to splunk --url $URL --token $TOK   # Splunk HEC
mftparse ... --format json | cognis-connect emit --to elastic --url $URL --token $TOK   # Elastic _bulk
```

Recommended for this domain: **stix, misp, splunk, elastic**. The full set is
`stix · taxii · misp · sigma · splunk · elastic · slack · discord · webhook · brief`.

## From Python

`normalize()` maps any record (field/indicator aliases handled) into a `Finding`, so this
works whatever `mftparse` outputs:

```python
from cognis_connect import normalize, stix
findings = [normalize(rec, source="mftparse") for rec in records]   # records = your JSON output
print(stix.to_bundle(findings))
```

## Other channels

- **AI enrichment / summaries** — point add-ins at an [`edgemesh`](https://github.com/cognis-digital/edgemesh)
  `/v1` gateway (`OPENAI_BASE_URL`); `cognis-connect emit --to brief` writes an analyst summary.
- **Composition patterns & reference stacks** — see [INTEROP.md](INTEROP.md).

> Integration backbone for the 300+ suite. **[github.com/cognis-digital](https://github.com/cognis-digital)**
