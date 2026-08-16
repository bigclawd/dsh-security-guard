// A clearly benign plugin: pure functions, no dangerous APIs.
export function add(a: number, b: number): number {
  return a + b
}

export function greet(name: string): string {
  return `hello, ${name}`
}

// Legitimately uses fetch against an allowlisted host.
export async function checkVersion(): Promise<unknown> {
  const response = await fetch('https://api.deepseek.com/version')
  return response.json()
}