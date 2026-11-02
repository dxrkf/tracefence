#!/usr/bin/env python3
"""Offline, redacted sensitive-data flow review for explicitly instrumented traces."""
import argparse
import base64
import html
import json
import sys
from pathlib import Path
from urllib.parse import quote, quote_plus

MAX_LINE = 2_000_000
MAX_SECRET = 8192
MAX_SECRETS = 500
MAX_DEPTH = 32


def variants(value):
    raw = value.encode('utf-8')
    candidates = [('plain', value), ('url', quote(value, safe='')),
                  ('form-url', quote_plus(value, safe='')),
                  ('base64', base64.b64encode(raw).decode()),
                  ('base64url', base64.urlsafe_b64encode(raw).decode()),
                  ('hex', raw.hex()), ('HEX', raw.hex().upper())]
    # Unpadded Base64 is common in URLs. One representation can have several names.
    candidates += [(name + '-unpadded', text.rstrip('=')) for name, text in candidates
                   if name in ('base64', 'base64url')]
    seen = set()
    for name, text in candidates:
        if text not in seen:
            seen.add(text)
            yield name, text


def leaves(value, path='$', depth=0):
    if depth > MAX_DEPTH:
        raise ValueError('payload nesting exceeds 32 levels')
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            # Keys may themselves carry data; inspect both keys and values.
            yield path + '[key]', key
            yield from leaves(child, path + '[' + json.dumps(key, ensure_ascii=True) + ']', depth + 1)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from leaves(child, path + '[' + str(i) + ']', depth + 1)
    elif value is not None and not isinstance(value, bool):
        yield path, str(value)


def name(value, field):
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError(field + ' must be a nonempty string of at most 200 characters')
    return value


def read_events(path):
    with Path(path).open('rb') as stream:
        line_number = 0
        while True:
            raw = stream.readline(MAX_LINE + 1)
            if not raw:
                break
            line_number += 1
            if len(raw) > MAX_LINE:
                raise ValueError('line ' + str(line_number) + ': exceeds 2 MB')
            if not raw.strip():
                continue
            try:
                yield line_number, json.loads(raw)
            except (UnicodeError, ValueError):
                # JSON diagnostics may contain sensitive snippets: never echo them.
                raise ValueError('line ' + str(line_number) + ': invalid UTF-8 JSON') from None


def audit(events, min_length=12):
    sources, patterns, all_patterns = [], [], set()
    identifiers, findings = set(), []
    sinks = 0
    for line, event in events:
        try:
            if not isinstance(event, dict):
                raise ValueError('event must be an object')
            kind = event.get('kind')
            required = {'kind', 'id', 'tool', 'secrets'} if kind == 'source' else {'kind', 'id', 'tool', 'destination', 'payload'}
            if kind not in ('source', 'sink') or set(event) != required:
                raise ValueError('unknown event kind or incorrect fields')
            eid = name(event['id'], 'id')
            tool = name(event['tool'], 'tool')
            if eid in identifiers:
                raise ValueError('duplicate event id')
            identifiers.add(eid)
            if kind == 'source':
                secrets = event['secrets']
                if not isinstance(secrets, list) or not secrets:
                    raise ValueError('source secrets must be a nonempty array')
                labels = set()
                for entry in secrets:
                    if not isinstance(entry, dict) or set(entry) != {'label', 'value'}:
                        raise ValueError('secret needs exactly label and value')
                    label = name(entry['label'], 'label')
                    if label in labels:
                        raise ValueError('duplicate source label')
                    labels.add(label)
                    value = entry['value']
                    if not isinstance(value, str) or not min_length <= len(value) <= MAX_SECRET:
                        raise ValueError('secret length outside configured bounds')
                    if len(patterns) >= MAX_SECRETS:
                        raise ValueError('maximum 500 secret records exceeded')
                    forms = list(variants(value))
                    patterns.append((eid, tool, label, forms))
                    all_patterns.update(text for _, text in forms)
                sources.append(eid)
            else:
                destination = event['destination']
                if not isinstance(destination, str) or not destination:
                    raise ValueError('destination must be a nonempty string')
                sinks += 1
                fields = list(leaves(event['payload'])) + [('destination', destination)]
                for source_id, source_tool, label, forms in patterns:
                    hits = []
                    for path, value in fields:
                        for encoding, token in forms:
                            if token in value:
                                hits.append(dict(field=path, encoding=encoding))
                                break
                    if hits:
                        findings.append(dict(source=source_id, source_tool=source_tool,
                                             sink=eid, sink_tool=tool, label=label, matches=hits))
        except (ValueError, TypeError, RecursionError):
            # Avoid rendering input-derived errors or metadata that may contain secrets.
            raise ValueError('line ' + str(line) + ': invalid trace event; check schema and limits') from None
    report = dict(schema='tracefence-report-v1', sources=len(sources), sinks=sinks,
                  finding_count=len(findings), findings=findings,
                  interpretation='Matching data flow requires review; intent and authorization are unknown.')
    # Scrub user-controlled metadata too, including labels and JSON field paths.
    tokens = sorted(all_patterns, key=len, reverse=True)
    def scrub(obj):
        if isinstance(obj, str):
            for token in tokens:
                obj = obj.replace(token, '[REDACTED]')
            return obj
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(v) for v in obj]
        return obj
    return scrub(report)


def render_html(report):
    escaped = html.escape(json.dumps(report, indent=2, ensure_ascii=True))
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>TraceFence audit</title><style>body{background:#0b1220;color:#e2e8f0;font:16px system-ui;max-width:1000px;margin:60px auto;padding:24px}h1{color:#5eead4}pre{background:#152238;padding:24px;border-radius:16px;white-space:pre-wrap;overflow-wrap:anywhere}p{line-height:1.6}</style>
<h1>TraceFence / data flow review</h1><p>Offline analysis. Known sensitive values are redacted. Matches are review evidence, not proof of an attack.</p><pre>''' + escaped + '</pre></html>'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('trace', help='JSONL trace using the documented source/sink schema')
    p.add_argument('--json', action='store_true')
    p.add_argument('--html', type=Path, help='write a standalone redacted HTML report')
    p.add_argument('--min-length', type=int, default=12)
    p.add_argument('--fail-on-findings', action='store_true')
    args = p.parse_args()
    try:
        if not 8 <= args.min_length <= MAX_SECRET:
            raise ValueError('min-length must be between 8 and 8192')
        if args.html and args.html.resolve() == Path(args.trace).resolve():
            raise ValueError('HTML output must differ from input')
        report = audit(read_events(args.trace), args.min_length)
        if args.html:
            args.html.write_text(render_html(report), encoding='utf-8')
    except (OSError, ValueError, RecursionError):
        print('error: invalid/unreadable trace or unwritable report; check schema and limits', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(f"TraceFence: {report['sources']} sources, {report['sinks']} sinks, {report['finding_count']} flow finding(s)")
        for f in report['findings']:
            # JSON quoting prevents control characters in metadata from controlling a terminal.
            route = json.dumps({k: f[k] for k in ('source','sink','label')}, ensure_ascii=True)
            encodings = ', '.join(sorted({m['encoding'] for m in f['matches']}))
            print(route + ' | ' + encodings)
        print('Known values redacted. No network requests or tools invoked.')
    return int(args.fail_on_findings and report['finding_count'] > 0)


if __name__ == '__main__':
    sys.exit(main())
