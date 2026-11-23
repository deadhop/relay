// Print a Markdown table of a benchmark run: node bench/summary.mjs <dir>
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const dir = process.argv[2];
const rows = readdirSync(dir)
  .filter((f) => f.endsWith('.json') && f !== 'smoke.json')
  .map((f) => [f.replace('.json', ''), JSON.parse(readFileSync(join(dir, f), 'utf8'))]);
const n = (x) => x.toLocaleString('en-US');
const lines = [
  '| Run | Round trips/s | Requests sent | Delivered to service | Answers delivered | Dropped | p50 / p99 ms | Attack messages | Relay peak RSS |',
  '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |',
  ...rows.map(([name, d]) =>
    `| ${name} | ${n(Math.round(d.throughput_round_trips_per_sec))} | ${n(d.requests_sent)} | ${n(d.requests_at_service)} | ${n(d.replies_at_client)} | ${d.dropped_requests + d.dropped_replies} | ${d.latency_ms.p50.toFixed(1)} / ${d.latency_ms.p99.toFixed(1)} | ${n(d.attack.messages_sent)} | ${(d.relay.rss_peak_kib / 1024).toFixed(0)} MiB |`,
  ),
];
writeFileSync(join(dir, 'summary.md'), lines.join('\n') + '\n');
console.log(lines.join('\n'));
