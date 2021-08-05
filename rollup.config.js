import { keys } from 'lodash';
import pkg from './package.json';

export default [
  {
    input: 'src/index.js',
    external: [
      'os',
      'fs',
      'path',
      ...keys(pkg.dependencies),
      ...keys(pkg.peerDependencies),
    ],
    output: [
      {
        file: pkg.main,
        format: 'cjs',
        interop: false,
        esModule: false,
        preferConst: true,
        strict: true,
      },
      { file: pkg.module, format: 'es' },
    ],
  },
];
