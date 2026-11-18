// Runs the whole analysis off the UI thread.
import { analyze } from './engine.js';
import { fromBlob, fromHttp } from './image/source.js';

const LAZY = /\.(e01|e\d\d|ex01|raw|dd|img|\d{3}|vhdx?|qcow2?|bin|disk|mem|vmem|dmp)$/i;

self.onmessage = async (e) => {
  // big files and disk images stay on disk and are read on demand; everything else is loaded
  const inputs = [];
  for (const f of e.data.files) {
    if (f.http) inputs.push({ name: f.name, src: fromHttp(`/api/image/read?path=${encodeURIComponent(f.http.path)}`, f.http.size, f.name, { 'X-Sudo-Z': '1' }) });
    else if (f.buf) inputs.push({ name: f.name, data: new Uint8Array(f.buf) });
    else if (LAZY.test(f.name) || f.file.size > 512 * 1024 ** 2) inputs.push({ name: f.name, src: fromBlob(f.file, f.name) });
    else inputs.push({ name: f.name, data: new Uint8Array(await f.file.arrayBuffer()) });
  }
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
