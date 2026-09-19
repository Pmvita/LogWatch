import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { loadEventsFromFile } from './load.ts'
import { formatIncidentNote } from './report.ts'
import { triage } from './triage.ts'

function parseArgs(argv: string[]): { input: string; out: string | null } {
  const args = argv.slice(2)
  let out: string | null = null
  const positional: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--out') {
      out = args[i + 1] ?? null
      i += 1
      continue
    }
    positional.push(args[i])
  }
  return {
    input: positional[0] ?? 'samples/cloudtrail.json',
    out,
  }
}

const { input, out } = parseArgs(process.argv)
const events = loadEventsFromFile(resolve(input))
const markdown = formatIncidentNote(triage(events))

if (out) {
  const dest = resolve(out)
  mkdirSync(dirname(dest), { recursive: true })
  writeFileSync(dest, markdown, 'utf8')
}

process.stdout.write(markdown)
