// rollup.config.js
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import peerDepsExternal from 'rollup-plugin-peer-deps-external';
import { terser } from 'rollup-plugin-terser';
import babel from '@rollup/plugin-babel';
import typescript from '@rollup/plugin-typescript';

export default {
  input: 'src/index.tsx', // Ensure the entry file is TypeScript
  output: [
    {
      file: 'dist/index.js',
      format: 'cjs', // CommonJS
      sourcemap: true,
      exports: 'named',
    },
    {
      file: 'dist/index.es.js',
      format: 'es', // ES Module
      sourcemap: true,
    },
    {
      file: 'dist/index.umd.js',
      format: 'umd', // UMD for broader compatibility
      name: 'WebEncryption',
      sourcemap: true,
      globals: {
        react: 'React',
      },
    },
  ],
  plugins: [
    peerDepsExternal(), // Exclude peer dependencies
    resolve({ extensions: ['.js', '.ts'] }), // Resolve modules
    commonjs(), // Convert CommonJS modules to ES6
    typescript({
      tsconfig: './tsconfig.json',
      declaration: true,
      declarationDir: 'dist',
      exclude: ['node_modules/**'],
    }),
    babel({
      exclude: 'node_modules/**',
      babelHelpers: 'bundled',
      presets: ['@babel/preset-env', '@babel/preset-react', '@babel/preset-typescript'],
    }),
    terser(), // Minify the output
  ],
  external: ['react'], // Prevent React from being bundled
};
