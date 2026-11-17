// Runs the whole analysis off the UI thread.
import { analyze } from './engine.js';

self.onmessage = async (e) => {
  const inputs = e.data.files.map((f) => ({ name: f.name, data: new Uint8Array(f.buf) }));
  try {
    let last = 0;
    const rep = await analyze(inputs, {
      onProgress: (p, label) => { const now = Date.now(); if (now - last > 60 || p >= 0.99) { last = now; self.postMessage({ type: 'progress', p, label }); } },
    });
    self.postMessage({ type: 'done', rep });
  } catch (err) {
    self.postMessage({ type: 'error', message: err.message, stack: err.stack });
  }
};
