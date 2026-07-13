import resolve from '@rollup/plugin-node-resolve';
import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const runtimeIndex = path.resolve(__dirname, 'src/runtime/index.js');

// Replace runtime/index.js with a concrete implementation using a custom plugin.
function runtimeSubstitute(impl) {
  const target = path.resolve(__dirname, 'src/runtime', impl);
  return {
    name: 'runtime-substitute',
    resolveId(source, importer) {
      if (!importer) return null;
      const resolved = path.resolve(path.dirname(importer), source);
      if (resolved === runtimeIndex) return target;
      return null;
    },
  };
}

export default [
  // ── Browser bundle ─────────────────────────────────────────────────────────
  {
    input: 'src/index.js',
    output: {
      file: 'dist/encedo-pgp.browser.js',
      format: 'es',
      sourcemap: true,
    },
    // openpgp is NOT bundled — it is imported so the host provides a single
    // instance (webpack in carbonio-pgp-ui, an import map in pgp-test.html).
    // Embedding it caused two openpgp copies in the plugin, and webpack
    // re-processing the embedded copy corrupted its internals (ZBASE32 /
    // PacketList.fromBinary). As an external import there is one shared instance.
    external: ['openpgp'],
    plugins: [
      runtimeSubstitute('browser-crypto.js'),
      resolve({ browser: true, preferBuiltins: false }),
    ],
  },

  // ── Node.js bundle ─────────────────────────────────────────────────────────
  {
    input: 'src/index.js',
    output: {
      file: 'dist/encedo-pgp.node.js',
      format: 'es',
      sourcemap: true,
    },
    plugins: [
      runtimeSubstitute('node-crypto.js'),
      resolve({ preferBuiltins: true }),
    ],
    external: ['openpgp', 'node:crypto', 'node:https', 'node:http', 'node:url'],
  },
];
