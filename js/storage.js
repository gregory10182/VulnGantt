const Storage = (() => {
  const KEY = 'vulngantt_data';
  const TYPES = [
    { description: 'Datos VulnGantt (JSON)', accept: { 'application/json': ['.json'] } }
  ];

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function save(data) {
    try {
      localStorage.setItem(KEY, JSON.stringify(data));
    } catch (e) {
      console.error('No se pudo guardar en localStorage', e);
    }
  }

  async function saveToFile(data, existingHandle) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });

    if (window.showSaveFilePicker) {
      let handle = existingHandle;
      if (!handle) {
        handle = await window.showSaveFilePicker({
          suggestedName: 'vulngantt.json',
          types: TYPES
        });
      }
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
      return { handle: handle, name: handle.name };
    }

    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vulngantt.json';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(a.href);
      a.remove();
    }, 1000);
    return { handle: null, name: a.download };
  }

  async function parseFile(file) {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data || !Array.isArray(data.vulnerabilidades)) {
      throw new Error('El archivo no tiene el formato esperado de VulnGantt');
    }
    return data;
  }

  return { load: load, save: save, saveToFile: saveToFile, parseFile: parseFile };
})();
