#!/usr/bin/env python3
"""Exercise a built CLI using disposable data and a loopback socket; emit aggregates only."""
import json
import pathlib
import socket
import subprocess
import sys
import tempfile

binary = str(pathlib.Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='shugo-runtime-') as temporary:
    root = pathlib.Path(temporary)
    data = root / 'data'
    def run(*args):
        result = subprocess.run([binary, '--data-dir', str(data), '--json', *args],
                                capture_output=True, text=True, timeout=130)
        if result.returncode != 0:
            raise RuntimeError('CLI smoke command failed (raw output withheld)')
        return result.stdout
    version = subprocess.check_output([binary, '--version'], text=True).strip()
    scan = json.loads(run('scan'))
    assert scan['checks'] and scan['status'] in ('completed', 'partial')
    log = root / 'synthetic-access.log'
    log.write_text('203.0.113.7 - - [08/Oct/2026:12:00:00 +0000] "GET /?test_secret=hidden HTTP/1.1" 200 12\n')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        with socket.create_connection(listener.getsockname()) as client:
            accepted, _ = listener.accept()
            with accepted:
                net = json.loads(run('connections'))
                assert net['status'] in ('observed', 'partial')
                assert any(c['localPort'] == listener.getsockname()[1] for c in net['connections'])
                events = run('watch', '--interval', '1', '--count', '2', '--connections', '--access-log', str(log))
    assert 'test_secret' not in events and 'HTTP/1.1' not in events
    events = [json.loads(line) for line in events.splitlines()]
    assert len(events) == 2 and all(e['accessLog']['linesCounted'] == 1 for e in events)
    snapshot = json.loads(run('status'))
    assert snapshot['cloudEnabled'] is False
    assert snapshot['budget']['patrolCalls'] == snapshot['budget']['resolverCalls'] == 0
    print(json.dumps({'version': version, 'scan_checks': len(scan['checks']),
                      'loopback_observed': True, 'watch_events': len(events),
                      'log_raw_secret_absent': True, 'cloud_enabled': False,
                      'api_calls': 0, 'scope': 'local CLI, disposable data, TCP loopback'}, indent=2))
