import init, { parse_binary } from './wasm-parser/pkg/wasm_parser.js';

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const outputContainer = document.getElementById('output-container');
const output = document.getElementById('output');
const clearBtn = document.getElementById('clear-btn');

let wasmReady = false;

async function loadWasm() {
  try {
    await init();
    wasmReady = true;
    console.log('Low-level WASM parser engine mounted successfully.');
  } catch (err) {
    outputContainer.style.display = 'block';
    output.textContent = `Runtime Exception: Failed to initialize WebAssembly core: ${err.message}`;
  }
}
loadWasm();

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('drag-over');
});
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const files = e.dataTransfer.files;
  if (files.length > 0) {
    handleFile(files[0]);
  }
});

dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files.length > 0) {
    handleFile(fileInput.files[0]);
  }
});

clearBtn.addEventListener('click', () => {
  outputContainer.style.display = 'none';
  output.textContent = '';
});

async function handleFile(file) {
  if (!wasmReady) {
    outputContainer.style.display = 'block';
    output.textContent = 'Compiling pipeline state... Native WASM engine is not ready yet.';
    return;
  }

  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  try {
    const jsonStr = parse_binary(bytes);
    const parsed = JSON.parse(jsonStr);
    const pretty = JSON.stringify(parsed, null, 2);
    output.textContent = pretty;
    outputContainer.style.display = 'block';
  } catch (err) {
    output.textContent = `Evaluation Error: Pipeline failed parsing bytecode: ${err.message}`;
    outputContainer.style.display = 'block';
  }
}
