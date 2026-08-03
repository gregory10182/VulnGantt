const Gantt = (() => {
  const DAY = 86400000;

  function parseDate(s) {
    if (!s) return null;
    const parts = String(s).split('-').map(Number);
    if (parts.length !== 3 || parts.some(isNaN)) return null;
    return new Date(parts[0], parts[1] - 1, parts[2]);
  }

  function fmtShort(d) {
    return String(d.getDate()).padStart(2, '0') + '/' + String(d.getMonth() + 1).padStart(2, '0');
  }

  function startOfWeek(d) {
    const x = new Date(d);
    const wd = (x.getDay() + 6) % 7;
    x.setDate(x.getDate() - wd);
    return x;
  }

  function daysBetween(a, b) {
    return Math.round((b - a) / DAY);
  }

  function colEnd(mode, start) {
    const e = new Date(start);
    if (mode === 'day') {
      e.setDate(e.getDate() + 1);
    } else if (mode === 'week') {
      e.setDate(e.getDate() + 7);
    } else {
      e.setDate(1);
      e.setMonth(e.getMonth() + 1);
    }
    return e;
  }

  function buildColumns(minDate, maxDate) {
    const total = daysBetween(minDate, maxDate);
    let mode = 'day';
    if (total > 60) mode = 'week';
    if (total > 400) mode = 'month';

    const cols = [];
    let d;
    if (mode === 'day') d = new Date(minDate);
    else if (mode === 'week') d = startOfWeek(minDate);
    else d = new Date(minDate.getFullYear(), minDate.getMonth(), 1);

    while (d <= maxDate) {
      cols.push(new Date(d));
      d = colEnd(mode, d);
    }
    if (cols.length === 0) cols.push(new Date(minDate));
    return { cols: cols, mode: mode };
  }

  function colIndex(cols, mode, date) {
    for (let i = 0; i < cols.length; i++) {
      if (date < colEnd(mode, cols[i])) return i;
    }
    return cols.length - 1;
  }

  function render(container, etapas, opts) {
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);

    const withDates = etapas.map(function (e) {
      return { key: e.key, nombre: e.nombre, color: e.color, inicio: e.inicio, fin: e.fin, s: parseDate(e.inicio), f: parseDate(e.fin) };
    });

    let minDate = null, maxDate = null;
    withDates.forEach(function (e) {
      if (e.s && (!minDate || e.s < minDate)) minDate = e.s;
      if (e.f && (!maxDate || e.f > maxDate)) maxDate = e.f;
    });
    if (!minDate) minDate = new Date(hoy);
    if (!maxDate || maxDate < minDate) maxDate = new Date(minDate);
    minDate.setDate(minDate.getDate() - 2);
    maxDate.setDate(maxDate.getDate() + 3);

    const built = buildColumns(minDate, maxDate);
    const cols = built.cols;
    const mode = built.mode;
    const N = cols.length;

    container.innerHTML = '';

    const editor = document.createElement('div');
    editor.className = 'gantt-editor';

    withDates.forEach(function (e) {
      const item = document.createElement('div');
      item.className = 'gantt-editor-item';
      item.style.setProperty('--c', e.color);
      item.innerHTML =
        '<span class="ge-dot"></span><span class="ge-name"></span>' +
        '<label>Inicio <input type="date"></label>' +
        '<label>Fin <input type="date"></label>';
      item.querySelector('.ge-name').textContent = e.nombre;
      const inpIni = item.querySelectorAll('input')[0];
      const inpFin = item.querySelectorAll('input')[1];
      inpIni.value = e.inicio || '';
      inpFin.value = e.fin || '';

      function commit() {
        opts.onEdit(e.key, inpIni.value || null, inpFin.value || null);
      }
      inpIni.addEventListener('change', commit);
      inpFin.addEventListener('change', commit);
      editor.appendChild(item);
    });
    container.appendChild(editor);

    const chart = document.createElement('div');
    chart.className = 'gantt-chart';
    chart.style.gridTemplateColumns = '172px repeat(' + N + ', minmax(18px, 1fr))';

    const corner = document.createElement('div');
    corner.className = 'gantt-corner';
    corner.textContent = 'Etapa';
    chart.appendChild(corner);

    cols.forEach(function (c, i) {
      const h = document.createElement('div');
      h.className = 'gantt-colhead';
      if (mode === 'day') {
        h.textContent = fmtShort(c);
      } else if (mode === 'week') {
        h.textContent = 'Sem ' + (i + 1) + ' · ' + fmtShort(c);
      } else {
        h.textContent = c.toLocaleDateString('es-ES', { month: 'short', year: '2-digit' });
      }
      chart.appendChild(h);
    });

    withDates.forEach(function (e, idx) {
      const label = document.createElement('div');
      label.className = 'gantt-label' + (idx % 2 ? ' alt' : '');
      const dot = document.createElement('span');
      dot.className = 'gl-dot';
      dot.style.background = e.color;
      label.appendChild(dot);
      const name = document.createElement('span');
      name.textContent = e.nombre;
      label.appendChild(name);
      chart.appendChild(label);

      const track = document.createElement('div');
      track.className = 'gantt-track' + (idx % 2 ? ' alt' : '');
      track.style.gridColumn = '2 / span ' + N;

      if (e.s && e.f) {
        const i0 = colIndex(cols, mode, e.s);
        const i1 = colIndex(cols, mode, e.f);
        const bar = document.createElement('div');
        bar.className = 'gantt-bar';
        bar.style.left = (i0 / N * 100) + '%';
        bar.style.width = Math.max((i1 - i0 + 1) / N * 100, 0.5) + '%';
        bar.style.background = e.color;
        bar.title = e.nombre + ': ' + (e.inicio || '?') + ' a ' + (e.fin || '?');
        bar.setAttribute('aria-label', e.nombre + ': del ' + (e.inicio || '?') + ' al ' + (e.fin || '?'));
        if (N <= 60) bar.textContent = fmtShort(e.s) + ' - ' + fmtShort(e.f);
        track.appendChild(bar);
      } else {
        const ph = document.createElement('div');
        ph.className = 'gantt-bar ghost';
        ph.textContent = 'Sin fechas';
        ph.setAttribute('aria-label', e.nombre + ': sin fechas asignadas');
        track.appendChild(ph);
      }

      if (hoy >= minDate && hoy <= maxDate) {
        const tl = document.createElement('div');
        tl.className = 'gantt-today';
        tl.style.left = (colIndex(cols, mode, hoy) / N * 100) + '%';
        track.appendChild(tl);
      }

      chart.appendChild(track);
    });

    container.appendChild(chart);
  }

  function renderSummary(container, items, opts) {
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);

    const withDates = items.map(function (it) {
      return { id: it.id, titulo: it.titulo, color: it.color, inicio: it.inicio, fin: it.fin, s: parseDate(it.inicio), f: parseDate(it.fin) };
    });

    let minDate = null, maxDate = null;
    withDates.forEach(function (e) {
      if (e.s && (!minDate || e.s < minDate)) minDate = e.s;
      if (e.f && (!maxDate || e.f > maxDate)) maxDate = e.f;
    });
    if (!minDate) minDate = new Date(hoy);
    if (!maxDate || maxDate < minDate) maxDate = new Date(minDate);
    minDate.setDate(minDate.getDate() - 2);
    maxDate.setDate(maxDate.getDate() + 3);

    const built = buildColumns(minDate, maxDate);
    const cols = built.cols;
    const mode = built.mode;
    const N = cols.length;

    container.innerHTML = '';
    if (!items.length) {
      const d = document.createElement('div');
      d.className = 'eq-empty';
      d.textContent = 'Sin datos para mostrar';
      container.appendChild(d);
      return;
    }

    const chart = document.createElement('div');
    chart.className = 'gantt-chart';
    chart.style.gridTemplateColumns = '172px repeat(' + N + ', minmax(18px, 1fr))';

    const corner = document.createElement('div');
    corner.className = 'gantt-corner';
    corner.textContent = 'Vulnerabilidad';
    chart.appendChild(corner);

    cols.forEach(function (c, i) {
      const h = document.createElement('div');
      h.className = 'gantt-colhead';
      if (mode === 'day') {
        h.textContent = fmtShort(c);
      } else if (mode === 'week') {
        h.textContent = 'Sem ' + (i + 1) + ' · ' + fmtShort(c);
      } else {
        h.textContent = c.toLocaleDateString('es-ES', { month: 'short', year: '2-digit' });
      }
      chart.appendChild(h);
    });

    withDates.forEach(function (e, idx) {
      const label = document.createElement('div');
      label.className = 'gantt-label' + (idx % 2 ? ' alt' : '');
      const t = document.createElement('span');
      t.textContent = e.titulo;
      label.appendChild(t);
      chart.appendChild(label);

      const track = document.createElement('div');
      track.className = 'gantt-track' + (idx % 2 ? ' alt' : '');
      track.style.gridColumn = '2 / span ' + N;

      if (e.s && e.f) {
        const i0 = colIndex(cols, mode, e.s);
        const i1 = colIndex(cols, mode, e.f);
        const bar = document.createElement('div');
        bar.className = 'gantt-bar sum-bar';
        bar.style.left = (i0 / N * 100) + '%';
        bar.style.width = Math.max((i1 - i0 + 1) / N * 100, 0.5) + '%';
        bar.style.background = e.color;
        bar.title = e.titulo + ': ' + (e.inicio || '?') + ' a ' + (e.fin || '?');
        bar.setAttribute('aria-label', 'Remediación de ' + e.titulo + ': del ' + (e.inicio || '?') + ' al ' + (e.fin || '?'));
        bar.addEventListener('click', function () {
          if (opts && opts.onSelect) opts.onSelect(e.id);
        });
        if (N <= 60) bar.textContent = fmtShort(e.s) + ' - ' + fmtShort(e.f);
        track.appendChild(bar);
      } else {
        const ph = document.createElement('div');
        ph.className = 'gantt-bar ghost';
        ph.textContent = 'Sin fechas';
        ph.setAttribute('aria-label', e.titulo + ': sin fechas de remediación');
        track.appendChild(ph);
      }

      if (hoy >= minDate && hoy <= maxDate) {
        const tl = document.createElement('div');
        tl.className = 'gantt-today';
        tl.style.left = (colIndex(cols, mode, hoy) / N * 100) + '%';
        track.appendChild(tl);
      }

      chart.appendChild(track);
    });

    container.appendChild(chart);
  }

  return { render: render, renderSummary: renderSummary };
})();
