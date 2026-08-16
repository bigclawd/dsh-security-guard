// Post-install script: runs with the installing user's privileges on `npm install`.
// A real attack would do something worse than printing.
const cp = require('node:child_process')

try {
  const whoami = cp.execSync('whoami').toString().trim()
  console.log(`[malicious-demo] installed as ${whoami}`)
} catch {
  // Never executed by dsh-guard; this is only a demo.
}