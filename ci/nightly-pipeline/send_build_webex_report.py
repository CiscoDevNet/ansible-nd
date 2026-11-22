#!/usr/bin/env python3
"""Render an ND nightly Webex report from a closed aggregate.json and optionally send it."""

import argparse
import base64
import getpass
import json
import os
import sys
import urllib.error
import urllib.request

ROOMS = {
    "private": "00000000-0000-4000-8000-000000000002",
    "public": "00000000-0000-4000-8000-000000000001",
}
WEBEX_URL = "https://webexapis.com/v1/messages"
PART_LIMIT = 7000


def load_report(path):
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # A saved console log prints the aggregate as one line starting with {"build":
    lines = [line for line in text.splitlines() if line.startswith('{"build":')]
    if not lines:
        raise SystemExit(f"{path}: no aggregate JSON line found")
    return json.loads(lines[-1])


def jenkins_groovy(messages, room_id):
    encoded = ",\n    ".join("'%s'" % base64.b64encode(m.encode("utf-8")).decode() for m in messages)
    return f"""// Paste into Manage Jenkins > Script Console. The token is never printed.
import com.cloudbees.plugins.credentials.CredentialsProvider
import org.jenkinsci.plugins.plaincredentials.StringCredentials
import groovy.json.JsonOutput
import jenkins.model.Jenkins

def roomId = '{room_id}'
def cred = CredentialsProvider.lookupCredentials(StringCredentials, Jenkins.instance, null, null).find {{ it.id == 'ANSIBLE_WEBEX_TOKEN' }}
if (!cred) {{ println 'ANSIBLE_WEBEX_TOKEN not found in the global credential store'; return }}
def parts = [
    {encoded}
]
parts.eachWithIndex {{ encodedPart, i ->
    def text = new String(encodedPart.decodeBase64(), 'UTF-8')
    def conn = new URL('{WEBEX_URL}').openConnection()
    conn.requestMethod = 'POST'
    conn.doOutput = true
    conn.connectTimeout = 30000
    conn.readTimeout = 30000
    conn.setRequestProperty('Authorization', 'Bearer ' + cred.secret.plainText)
    conn.setRequestProperty('Content-Type', 'application/json; charset=utf-8')
    conn.outputStream.withWriter('UTF-8') {{ it << JsonOutput.toJson([roomId: roomId, markdown: text]) }}
    println "Webex part ${{i + 1}}/${{parts.size()}}: HTTP ${{conn.responseCode}}"
    if (conn.responseCode != 200) {{ throw new Exception('Webex delivery failed; stopped before remaining parts') }}
    conn.disconnect()
}}
null
"""


def count(row, name):
    if row.get("result") == "NOT_RUN":
        return 0
    value = (row.get("case_totals") or {}).get(name)
    if type(value) is not int or value < 0:
        raise SystemExit(f"Row {row.get('module')} has no numeric '{name}' case count; refusing to report")
    return value


def clean(value, limit=None):
    text = " ".join(str(value or "").replace("|", "/").split())
    return text if limit is None or len(text) <= limit else text[: limit - 3] + "..."


def render_table(rows):
    groups = {}
    show_nd = len({row.get("nd") for row in rows}) > 1
    for row in sorted(rows, key=lambda row: row.get("sequence", 0)):
        scope = clean(row.get("scope"))
        round_name = row.get("round_label")
        if round_name not in ("iBGP", "eBGP"):
            round_name = "iBGP" if scope.startswith("iBGP") else "eBGP" if scope.startswith("eBGP") else "Other"
        kind = "VXLAN" if scope in ("iBGP", "eBGP") else scope.replace("iBGP+", "VXLAN+").replace("eBGP+", "VXLAN+")
        key = (row["module"], clean(row.get("nd")), kind)
        groups.setdefault(key, {}).setdefault(round_name, []).append(row)
    rounds = ["iBGP", "eBGP"]
    if any("Other" in group for group in groups.values()):
        rounds.append("Other")
    headers = ["Module"] + (["ND"] if show_nd else [])
    for round_name in rounds:
        headers.extend([round_name, "Passed", "Failed", "Skipped", "Time"])
    leading = 2 if show_nd else 1
    body = []
    for (module, nd, kind), group in groups.items():
        for index in range(max(len(executions) for executions in group.values())):
            cells = [clean(module)] + ([nd] if show_nd else [])
            for round_name in rounds:
                executions = group.get(round_name, [])
                if index >= len(executions):
                    cells.extend(["NOT_RUN", "0", "0", "0", "-"])
                    continue
                row = executions[index]
                status = "OK" if row["result"] == "PASS" else clean(row["result"])
                cells.extend([status, str(count(row, "passed")), str(count(row, "failed")),
                              str(count(row, "skipped")), "-" if status == "NOT_RUN" else clean(row.get("duration") or "-")])
            body.append(cells)
    widths = [max(len(r[i]) for r in [headers] + body) for i in range(len(headers))]

    def line(cells):
        return "  ".join(c.ljust(w) if i < leading or (i - leading) % 5 == 0 else c.rjust(w)
                         for i, (c, w) in enumerate(zip(cells, widths))).rstrip()

    return "```\n" + "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in body]) + "\n```"


def build_message(report, args):
    if str(report.get("build", "")) != str(args.build):
        raise SystemExit("Requested build does not match aggregate.json")
    if any(not row.get("test_type") and row.get("result") != "NOT_RUN" for row in report.get("rows", [])):
        raise SystemExit("Execution rows without a test type cannot establish integration totals")
    rows = [r for r in report.get("rows", []) if r.get("test_type") == "integration"]
    if not rows:
        raise SystemExit("aggregate.json contains no integration rows")
    if report.get("reporting_errors"):
        raise SystemExit("aggregate.json has reporting errors; refusing to report")
    for row in rows:
        if row.get("result") == "NOT_RUN":
            continue
        if row.get("validated") is not True:
            raise SystemExit("Unvalidated execution; refusing to report")
        counts = {name: count(row, name) for name in ("started", "passed", "failed", "skipped", "incomplete")}
        coverage = row.get("coverage")
        if coverage == "COMPLETE":
            valid = counts["incomplete"] == 0 and counts["started"] == counts["passed"] + counts["failed"]
        elif coverage == "INCOMPLETE":
            valid = counts["incomplete"] > 0 and counts["started"] == counts["passed"] + counts["failed"] + counts["incomplete"]
        else:
            valid = coverage == "NOT_STARTED" and all(value == 0 for value in counts.values())
        if not valid:
            raise SystemExit("Case counts do not match coverage; refusing to report")
    totals = {name: sum(count(r, name) for r in rows) for name in ("passed", "failed", "skipped")}
    nd = sorted({str(r.get("nd")) for r in rows if r.get("nd")})
    rounds = ["iBGP", "eBGP"]

    parts = [f"ND {', '.join(nd) or '4.3'} ({', '.join(rounds)}) NIGHTLY NOTIFICATION"]
    if args.note:
        parts += [args.note, ""]
    parts.append(f"📊 Pipeline completed for the ND Nightly run - Build {report.get('build', args.build)}")
    if args.branch:
        parts.append(f"🌿 ansible-nd branch: {args.branch}")
    if args.commit:
        parts.append(f"🔖 ansible-nd commit: {args.commit}")
    parts += ["", "INTEG TEST COUNTS", f"Passed: {totals['passed']}", f"Failed: {totals['failed']}",
              f"Skipped: {totals['skipped']}",
              "Counts are authored integration test cases only; setup, cleanup and pipeline checks are excluded."]
    if args.build_result:
        parts.append(f"Build result: {args.build_result}")
    parts += ["", "📝 DETAILED TEST RESULTS:", "", render_table(rows)]

    failures = [r for r in sorted(rows, key=lambda r: r.get("sequence", 0)) if r["result"] != "PASS"]
    if failures:
        parts += ["", "**Failure reasons:**"]
        for r in failures:
            note = "authored test operation not reached; " if r.get("coverage") == "NOT_STARTED" else ""
            parts.append(f"- {r['module']} ({clean(r.get('scope'))}; {clean(r.get('round_label'))} round): {note}{clean(r.get('failure') or 'see artifact', 160)}")
    incomplete_rows = [row for row in rows if (row.get("case_totals") or {}).get("incomplete", 0) > 0]
    if incomplete_rows:
        parts += ["", "**Incomplete verification:**"]
        for row in incomplete_rows:
            parts.append(f"- {row['module']} ({clean(row.get('round_label'))}): {count(row, 'incomplete')} incomplete case(s); not counted as passed, failed or skipped.")
    if args.job_url:
        parts += ["", "**Artifact links:**", f"- [Build artifacts]({args.job_url.rstrip('/')}/{args.build}/artifact/)"]
    if args.duration:
        parts.append(f"⏱️ **Total run duration:** {args.duration}")
    return "\n".join(parts)


def split_message(message, header, limit=PART_LIMIT):
    def size(text):
        return len(text.encode("utf-16-le")) // 2

    if size(message) <= limit:
        return [message]
    content_limit = limit - 80
    if size(header) + 8 >= content_limit:
        raise ValueError("Continuation header exceeds message capacity")
    parts, current, in_fence, table_head = [], "", False, []

    def flush():
        nonlocal current
        parts.append(current + ("```\n" if in_fence else ""))
        current = header + ("```\n" + "".join(line + "\n" for line in table_head) if in_fence else "")

    for raw in message.split("\n"):
        if size(current) + size(raw) + 1 + (4 if in_fence else 0) > content_limit and current:
            flush()
        while size(current) + size(raw) + 1 + (4 if in_fence else 0) > content_limit:
            available = content_limit - size(current) - 1 - (4 if in_fence else 0)
            if available <= 0:
                raise ValueError("Table header exceeds message capacity")
            boundary = 0
            used = 0
            for character in raw:
                used += size(character)
                if used > available:
                    break
                boundary += 1
            if boundary == 0:
                raise ValueError("Message capacity exhausted")
            current += raw[:boundary] + "\n"
            raw = raw[boundary:]
            flush()
        if raw.strip().startswith("```"):
            in_fence = not in_fence
            table_head = []
        elif in_fence and len(table_head) < 2:
            table_head.append(raw)
        current += raw + "\n"
    parts.append(current)
    total = len(parts)
    messages = [f"{part.rstrip()}\n\n_(part {index}/{total})_" for index, part in enumerate(parts, 1)]
    if any(size(part) > limit for part in messages):
        raise ValueError("Webex report part exceeds message limit")
    return messages


def send(messages, room_id, token):
    for index, text in enumerate(messages, 1):
        data = json.dumps({"roomId": room_id, "markdown": text}).encode("utf-8")
        request = urllib.request.Request(WEBEX_URL, data=data, method="POST", headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json; charset=utf-8"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                if response.status != 200:
                    raise SystemExit(f"Webex part {index}/{len(messages)} failed: HTTP {response.status}")
                print(f"Webex part {index}/{len(messages)} sent (HTTP {response.status})")
        except urllib.error.HTTPError as error:
            raise SystemExit(f"Webex part {index}/{len(messages)} failed: HTTP {error.code}")
        except urllib.error.URLError:
            raise SystemExit(f"Webex part {index}/{len(messages)} failed: connection error") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aggregate", required=True, help="aggregate.json, or a saved Jenkins consoleText containing it")
    parser.add_argument("--build", default="")
    parser.add_argument("--job-url", default="http://198.51.100.155:8080/job/Ansible-ND-Pipeline1/")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--build-result", default="")
    parser.add_argument("--duration", default="")
    parser.add_argument("--note", default="")
    parser.add_argument("--room", choices=sorted(ROOMS), default="private")
    parser.add_argument("--send", action="store_true", help="actually post; otherwise print only")
    parser.add_argument("--jenkins-groovy", metavar="PATH", help="write a Jenkins Script Console sender instead of posting")
    args = parser.parse_args()

    report = load_report(args.aggregate)
    args.build = args.build or str(report.get("build", ""))
    message = build_message(report, args)
    header = f"ND NIGHTLY NOTIFICATION - Build {args.build} (continued)\n\n"
    messages = split_message(message, header)
    for index, text in enumerate(messages, 1):
        print(f"----- part {index}/{len(messages)} ({len(text)} chars) -----\n{text}\n")
    if args.jenkins_groovy:
        with open(args.jenkins_groovy, "w", encoding="utf-8") as handle:
            handle.write(jenkins_groovy(messages, ROOMS[args.room]))
        print(f"Wrote Script Console sender for the {args.room} room: {args.jenkins_groovy}")
        return 0
    if not args.send:
        print("Dry run only; add --send to post.")
        return 0
    token = os.environ.get("WEBEX_TOKEN") or os.environ.get("ANSIBLE_WEBEX_TOKEN") or getpass.getpass("Webex bot token: ")
    if not token.strip():
        raise SystemExit("No Webex token provided")
    send(messages, ROOMS[args.room], token.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
