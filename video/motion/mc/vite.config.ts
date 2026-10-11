import {defineConfig} from 'vite';
import mcImport from '@motion-canvas/vite-plugin';
import ffImport from '@motion-canvas/ffmpeg';

// Both plugins ship as CJS; unwrap the default export when Vite bundles the config.
const motionCanvas = ((mcImport as any).default ?? mcImport) as typeof mcImport;
const ffmpeg = ((ffImport as any).default ?? ffImport) as typeof ffImport;

export default defineConfig({
  plugins: [motionCanvas(), ffmpeg()],
});
