/**
 * util.js — Shared test utilities.
 */

import readline from 'node:readline';

/** Parse --key value CLI arguments into a plain object. */
export function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        result[key] = next;
        i++;
      } else {
        result[key] = true;
      }
    }
  }
  return result;
}

/** Prompt for a value from stdin (used for passwords). */
export function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer);
    });
  });
}
