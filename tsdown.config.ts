import { defineConfig } from 'tsdown';

export default defineConfig({
  name: 'authflowy',
  entry: 'src/index.ts',
  outDir: 'dist',
  format: ['esm', 'cjs'],
  target: 'es2020',
  sourcemap: true,
  clean: true,
  exports: true,
  dts: true,
});
