import { defineConfig } from 'tsdown';

export default defineConfig({
  name: 'authingy',
  format: ['esm', 'cjs'],
  target: 'es2020',
  sourcemap: true,
  clean: true,
  dts: true,
  outDir: 'dist',
  entry: 'src/index.ts',
  exports: true,
});
