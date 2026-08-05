const ETAPAS = [
  { key: 'analisis', nombre: 'Análisis', color: '#3b82f6' },
  { key: 'aprobacion', nombre: 'Aprobación', color: '#8b5cf6' },
  { key: 'remediacion', nombre: 'Remediación', color: '#f59e0b' },
  { key: 'seguimiento', nombre: 'Seguimiento', color: '#10b981' }
];

const SEV = {
  critica: { label: 'Crítica', cls: 'sev-critica', color: '#dc2626' },
  alta: { label: 'Alta', cls: 'sev-alta', color: '#f97316' },
  media: { label: 'Media', cls: 'sev-media', color: '#eab308' },
  baja: { label: 'Baja', cls: 'sev-baja', color: '#22c55e' }
};

const ESTADOS_VULN = [
  ['abierta', 'Abierta'],
  ['en_proceso', 'En proceso'],
  ['en_revision', 'En revisión'],
  ['cerrada', 'Cerrada']
];

const ESTADOS_EQ = [
  ['apagado', 'Apagado'],
  ['sin_acceso', 'Sin acceso'],
  ['decomisado', 'Decomisado'],
  ['remediado', 'Remediado'],
  ['derivado', 'Derivado']
];

const ESTADOS_EQ_COLOR = {
  apagado: '#94a3b8',
  sin_acceso: '#f59e0b',
  decomisado: '#ef4444',
  remediado: '#16a34a',
  derivado: '#0ea5e9'
};

let modalLastFocus = null;

const state = {
  data: { version: 1, vulnerabilidades: [] },
  selectedId: null,
  fileHandle: null,
  fileName: null,
  dirty: false,
  editingEqId: null,
  editingVulnId: null,
  selectedEqs: new Set(),
  lastEqVuln: null,
  eqFilter: '',
  lastEqEstado: 'apagado'
};

function $(sel) { return document.querySelector(sel); }
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
function hoyISO() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function nowISO() { return new Date().toISOString(); }

function fmtFecha(s) {
  if (!s) return '';
  const parts = String(s).split('T')[0].split('-').map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) return String(s);
  return (parts[2] < 10 ? '0' : '') + parts[2] + '/' + (parts[1] < 10 ? '0' : '') + parts[1] + '/' + parts[0];
}
function addDays(iso, n) {
  const d = new Date(iso + 'T00:00:00');
  d.setDate(d.getDate() + n);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function sanitizeData(data) {
  const migrar = {
    pendiente: 'apagado',
    en_proceso: 'sin_acceso',
    remediado: 'decomisado',
    verificado: 'remediado',
    no_reparable: 'derivado'
  };
  const conocidos = ['apagado', 'sin_acceso', 'decomisado', 'remediado', 'derivado'];
  if (!data.vulnerabilidades) data.vulnerabilidades = [];
  data.vulnerabilidades.forEach(function (v) {
    if (!v.etapas || typeof v.etapas !== 'object') v.etapas = {};
    if (!Array.isArray(v.equipos)) v.equipos = [];
    v.equipos.forEach(function (e) {
      if (migrar[e.estado]) e.estado = migrar[e.estado];
      else if (!conocidos.includes(e.estado)) e.estado = 'apagado';
    });
  });
  return data;
}
function getSelected() {
  return state.data.vulnerabilidades.find(function (v) { return v.id === state.selectedId; }) || null;
}
function estadoLabel(list, key) {
  const f = list.find(function (e) { return e[0] === key; });
  return f ? f[1] : key;
}
function persist() {
  Storage.save(state.data);
  state.dirty = true;
  updateSaveStatus();
}

function flashMsg(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(flashMsg._t);
  flashMsg._t = setTimeout(function () { t.classList.remove('show'); }, 2600);
}

function updateSaveStatus() {
  const el = $('#saveStatus');
  el.classList.remove('dirty', 'ok');
  if (!state.fileName) {
    el.textContent = 'Sin archivo asignado';
  } else if (state.dirty) {
    el.textContent = 'Cambios sin guardar en ' + state.fileName;
    el.classList.add('dirty');
  } else {
    el.textContent = 'Guardado en ' + state.fileName;
    el.classList.add('ok');
  }
}

function newVuln() {
  const det = hoyISO();
  const etapas = {};
  ETAPAS.forEach(function (et, i) {
    const ini = addDays(det, i * 7);
    etapas[et.key] = { inicio: ini, fin: addDays(ini, 6) };
  });
  return {
    id: uid(),
    titulo: '',
    descripcion: '',
    severidad: 'media',
    estado: 'abierta',
    responsable: '',
    fecha_deteccion: det,
    creado: nowISO(),
    actualizado: nowISO(),
    etapas: etapas,
    equipos: []
  };
}

/* ---------------- Lista ---------------- */

function renderList() {
  const q = $('#searchInput').value.trim().toLowerCase();
  let list = state.data.vulnerabilidades.filter(function (v) {
    if (!q) return true;
    const hay = (v.titulo || '') + ' ' + (v.descripcion || '') + ' ' + (v.responsable || '');
    return hay.toLowerCase().includes(q);
  });
  list = list.slice().sort(function (a, b) {
    return (b.fecha_deteccion || '').localeCompare(a.fecha_deteccion || '');
  });

  const ul = $('#vulnList');
  ul.innerHTML = '';
  if (!list.length) {
    const li = document.createElement('li');
    li.className = 'vuln-empty';
    li.textContent = state.data.vulnerabilidades.length ? 'No hay coincidencias' : 'No hay vulnerabilidades todavía';
    ul.appendChild(li);
  }
  list.forEach(function (v) {
    const li = document.createElement('li');
    li.className = 'vuln-item' + (v.id === state.selectedId ? ' selected' : '');
    li.dataset.id = v.id;
    li.tabIndex = 0;
    li.setAttribute('role', 'button');
    li.setAttribute('aria-label', 'Abrir vulnerabilidad ' + (v.titulo || 'sin título'));
    const sev = SEV[v.severidad] || SEV.media;
    li.innerHTML =
      '<div class="vi-row">' +
      '<span class="badge ' + sev.cls + '">' + sev.label + '</span>' +
      '<span class="vi-est">' + esc(estadoLabel(ESTADOS_VULN, v.estado)) + '</span>' +
      '</div>' +
      '<div class="vi-title">' + esc(v.titulo || 'Sin título') + '</div>' +
      '<div class="vi-sub">' + esc(v.responsable || 'Sin responsable') + ' · ' + v.equipos.length + ' equipo(s)</div>';
    ul.appendChild(li);
  });

  const total = state.data.vulnerabilidades.length;
  const criticas = state.data.vulnerabilidades.filter(function (v) { return v.severidad === 'critica'; }).length;
  const pendientes = state.data.vulnerabilidades.filter(function (v) { return v.estado !== 'cerrada'; }).length;
  $('#sidebarStats').textContent = total + ' vulnerabilidad(es) · ' + criticas + ' crítica(s) · ' + pendientes + ' abierta(s)';
}

function selectVuln(id) {
  state.selectedId = id;
  showDetailView();
  renderList();
  renderDetail();
}

/* ---------------- Resumen ---------------- */

function showDetailView() {
  $('#summaryView').hidden = true;
  $('#detail').hidden = false;
  $('#btnSummary').classList.remove('active');
}

function showSummary() {
  $('#detail').hidden = true;
  $('#summaryView').hidden = false;
  $('#btnSummary').classList.add('active');
  renderSummaryView();
}

function etapaActualInfo(v) {
  if (v.estado === 'cerrada') return { nombre: 'Cerrada', color: '#94a3b8' };
  const hoy = hoyISO();
  for (let i = 0; i < ETAPAS.length; i++) {
    const et = v.etapas[ETAPAS[i].key];
    if (!et) continue;
    if (et.inicio && et.fin && hoy >= et.inicio && hoy <= et.fin) {
      return { nombre: ETAPAS[i].nombre, color: ETAPAS[i].color };
    }
  }
  for (let i = 0; i < ETAPAS.length; i++) {
    const et = v.etapas[ETAPAS[i].key];
    if (et && et.inicio && et.inicio > hoy) {
      return { nombre: 'Próxima: ' + ETAPAS[i].nombre, color: ETAPAS[i].color };
    }
  }
  return { nombre: 'Finalizado', color: '#16a34a' };
}

function equiposRemediados(v) {
  return v.equipos.filter(function (e) { return e.estado === 'remediado'; }).length;
}

function renderSummaryView() {
  const vulns = state.data.vulnerabilidades;
  const total = vulns.length;
  const criticas = vulns.filter(function (v) { return v.severidad === 'critica'; }).length;
  const enProceso = vulns.filter(function (v) { return v.estado !== 'cerrada'; }).length;
  const cerradas = vulns.filter(function (v) { return v.estado === 'cerrada'; }).length;
  let eqTotal = 0, eqRem = 0;
  vulns.forEach(function (v) {
    eqTotal += v.equipos.length;
    eqRem += equiposRemediados(v);
  });

  function kpi(label, value, cls) {
    return '<div class="kpi ' + cls + '"><div class="kpi-val">' + value + '</div><div class="kpi-label">' + label + '</div></div>';
  }

  $('#kpiGrid').innerHTML =
    kpi('Vulnerabilidades', total, 'kpi-total') +
    kpi('Críticas', criticas, 'kpi-crit') +
    kpi('En proceso', enProceso, 'kpi-proc') +
    kpi('Cerradas', cerradas, 'kpi-done') +
    kpi('Equipos afectados', eqTotal, 'kpi-total') +
    kpi('Equipos remediados', eqRem + (eqTotal ? ' (' + Math.round(eqRem / eqTotal * 100) + '%)' : ''), 'kpi-done');

  const sorted = vulns.slice().sort(function (a, b) {
    const w = { critica: 0, alta: 1, media: 2, baja: 3 };
    const d = (w[a.severidad] || 9) - (w[b.severidad] || 9);
    if (d !== 0) return d;
    return (b.fecha_deteccion || '').localeCompare(a.fecha_deteccion || '');
  });

  const tbody = $('#sumBody');
  tbody.innerHTML = '';
  if (!sorted.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'eq-empty';
    td.textContent = 'No hay vulnerabilidades todavía. Crea la primera desde el botón "+ Nueva vulnerabilidad".';
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  sorted.forEach(function (v) {
    const sev = SEV[v.severidad] || SEV.media;
    const ea = etapaActualInfo(v);
    let prog;
    if (!v.equipos.length) {
      prog = '—';
    } else {
      const rem = equiposRemediados(v);
      const pct = Math.round(rem / v.equipos.length * 100);
      prog = '<div class="sum-prog"><span class="sum-prog-bar" style="width:' + pct + '%"></span></div>' +
             '<span class="sum-prog-txt">' + rem + '/' + v.equipos.length + ' (' + pct + '%)</span>';
    }
    const tr = document.createElement('tr');
    tr.className = 'sum-row';
    tr.dataset.id = v.id;
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', 'Abrir vulnerabilidad ' + (v.titulo || 'sin título'));
    tr.innerHTML =
      '<td><span class="badge ' + sev.cls + '">' + sev.label + '</span></td>' +
      '<td class="sum-title">' + esc(v.titulo || 'Sin título') + '</td>' +
      '<td>' + esc(estadoLabel(ESTADOS_VULN, v.estado)) + '</td>' +
      '<td>' + esc(v.responsable || '—') + '</td>' +
      '<td>' + esc(fmtFecha(v.fecha_deteccion) || '—') + '</td>' +
      '<td>' + esc(fmtFecha(finGantt(v)) || '—') + '</td>' +
      '<td><span class="lg"><i style="background:' + ea.color + '"></i>' + ea.nombre + '</span></td>' +
      '<td>' + prog + '</td>';
    tbody.appendChild(tr);
  });

  const items = vulns.map(function (v) {
    const re = v.etapas.remediacion || {};
    return {
      id: v.id,
      titulo: v.titulo || 'Sin título',
      color: (SEV[v.severidad] || SEV.media).color,
      inicio: re.inicio || '',
      fin: re.fin || ''
    };
  });
  Gantt.renderSummary($('#sumGantt'), items, { onSelect: selectVuln });

  renderEquiposResumen(sorted);
}

function renderEquiposResumen(sorted) {
  const tbody = $('#eqStateBody');
  tbody.innerHTML = '';
  const rows = sorted.filter(function (v) { return v.equipos.length > 0; });
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8;
    td.className = 'eq-empty';
    td.textContent = 'Aún no hay equipos registrados en ninguna vulnerabilidad.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  rows.forEach(function (v) {
    const counts = {};
    ESTADOS_EQ.forEach(function (e) { counts[e[0]] = 0; });
    v.equipos.forEach(function (eq) {
      if (counts[eq.estado] !== undefined) counts[eq.estado]++;
    });
    const total = v.equipos.length;
    const segs = ESTADOS_EQ.map(function (e) {
      if (!counts[e[0]]) return '';
      const pct = Math.round(counts[e[0]] / total * 100);
      return '<span style="width:' + pct + '%;background:' + ESTADOS_EQ_COLOR[e[0]] + '" title="' + e[1] + ': ' + counts[e[0]] + '"></span>';
    }).join('');
    const tr = document.createElement('tr');
    tr.className = 'sum-row';
    tr.dataset.id = v.id;
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', 'Abrir vulnerabilidad ' + (v.titulo || 'sin título'));
    tr.innerHTML =
      '<td class="sum-title">' + esc(v.titulo || 'Sin título') + '</td>' +
      ESTADOS_EQ.map(function (e) { return '<td class="num-ct">' + counts[e[0]] + '</td>'; }).join('') +
      '<td class="num-ct strong">' + total + '</td>' +
      '<td><span class="stack-bar">' + segs + '</span></td>';
    tbody.appendChild(tr);
  });
}

function showEmpty() {
  $('#emptyState').hidden = false;
  $('#detailContent').hidden = true;
}

function finGantt(v) {
  let fin = '';
  ETAPAS.forEach(function (e) {
    const etapa = v.etapas[e.key] || {};
    if (etapa.fin && (!fin || etapa.fin > fin)) fin = etapa.fin;
  });
  return fin || '—';
}

/* ---------------- Detalle ---------------- */

function renderDetail() {
  const v = getSelected();
  if (!v) { showEmpty(); return; }
  $('#emptyState').hidden = true;
  $('#detailContent').hidden = false;

  const sev = SEV[v.severidad] || SEV.media;
  const badge = $('#sevBadge');
  badge.textContent = sev.label;
  badge.className = 'badge ' + sev.cls;
  $('#vulnTitle').textContent = v.titulo || 'Sin título';
  $('#vulnId').textContent = '#' + v.id;
  $('#vulnEstado').value = v.estado;
  $('#metaResp').textContent = v.responsable || '—';
  $('#metaDet').textContent = fmtFecha(v.fecha_deteccion) || '—';
  $('#metaFin').textContent = fmtFecha(finGantt(v)) || '—';
  $('#metaUpd').textContent = v.actualizado ? new Date(v.actualizado).toLocaleString('es-ES') : '—';
  $('#metaEq').textContent = String(v.equipos.length);
  $('#vulnDesc').textContent = v.descripcion || 'Sin descripción.';

  renderGantt(v);
  renderEquipos(v);
}

function renderGantt(v) {
  const etapasData = ETAPAS.map(function (e) {
    const etapa = v.etapas[e.key] || {};
    return { key: e.key, nombre: e.nombre, color: e.color, inicio: etapa.inicio || '', fin: etapa.fin || '' };
  });
  Gantt.render($('#ganttContainer'), etapasData, {
    onEdit: function (key, inicio, fin) {
      if (!v.etapas[key]) v.etapas[key] = {};
      v.etapas[key].inicio = inicio;
      v.etapas[key].fin = fin;
      v.actualizado = nowISO();
      persist();
      renderGantt(v);
      renderList();
    }
  });
}

/* ---------------- Equipos ---------------- */

function eqMatch(e, q) {
  if (!q) return true;
  return (e.nombre + ' ' + (e.ip || '') + ' ' + (e.so || '')).toLowerCase().includes(q);
}

function filteredEquipos(v) {
  return v.equipos.filter(function (e) { return eqMatch(e, state.eqFilter); });
}

function renderEquipos(v) {
  if (state.lastEqVuln !== v.id) {
    state.lastEqVuln = v.id;
    state.selectedEqs.clear();
    state.eqFilter = '';
    $('#eqSearch').value = '';
  }
  state.selectedEqs.forEach(function (id) {
    if (!v.equipos.some(function (e) { return e.id === id; })) state.selectedEqs.delete(id);
  });

  $('#eqCount').textContent = v.equipos.length + ' equipo(s)';
  const tbody = $('#eqBody');
  tbody.innerHTML = '';
  const visible = filteredEquipos(v);

  if (!v.equipos.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'eq-empty';
    td.textContent = 'Sin equipos registrados. Agrega los equipos afectados con su estado.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    $('#eqFilterCount').textContent = '';
    renderBulkBar(v);
    return;
  }

  if (!visible.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 7;
    td.className = 'eq-empty';
    td.textContent = 'Ningún equipo coincide con la búsqueda.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    $('#eqFilterCount').textContent = '0 de ' + v.equipos.length + ' resultado(s)';
    renderBulkBar(v);
    return;
  }

  $('#eqFilterCount').textContent = state.eqFilter ? visible.length + ' de ' + v.equipos.length + ' resultado(s)' : '';

  visible.forEach(function (eq, i) {
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td class="chk"><input type="checkbox" class="eq-chk" data-id="' + eq.id + '"' + (state.selectedEqs.has(eq.id) ? ' checked' : '') + '></td>' +
      '<td class="num">' + (i + 1) + '</td>' +
      '<td class="mono strong">' + esc(eq.nombre) + '</td>' +
      '<td>' + esc(eq.ip || '—') + '</td>' +
      '<td>' + esc(eq.so || '—') + '</td>' +
      '<td><select class="eq-estado" data-id="' + eq.id + '">' +
      ESTADOS_EQ.map(function (e) {
        return '<option value="' + e[0] + '"' + (e[0] === eq.estado ? ' selected' : '') + '>' + e[1] + '</option>';
      }).join('') +
      '</select></td>' +
      '<td><button class="btn btn-sm btn-edit" data-action="edit" data-id="' + eq.id + '">Editar</button> ' +
      '<button class="btn btn-sm btn-danger" data-action="del" data-id="' + eq.id + '">Eliminar</button></td>';
    tbody.appendChild(tr);
  });
  renderBulkBar(v);
}

function renderBulkBar(v) {
  const n = v ? v.equipos.length : 0;
  const sel = state.selectedEqs.size;
  $('#eqSelCount').textContent = sel + ' seleccionado(s)';
  $('#eqSelectAll').checked = n > 0 && sel === n;
}

function selectedEqIds(v) {
  return Array.from(state.selectedEqs).filter(function (id) {
    return v.equipos.some(function (e) { return e.id === id; });
  });
}

function bulkAddEquipos(v) {
  const lines = $('#bulkTextarea').value.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) {
    return l && !l.startsWith('#');
  });
  if (!lines.length) {
    flashMsg('Pega al menos una línea de equipos');
    return;
  }
  let agregados = 0, repetidos = 0;
  const estadoInicial = $('#bulkEstado').value || 'apagado';
  state.lastEqEstado = estadoInicial;
  const seen = new Set(v.equipos.map(function (e) { return e.nombre.trim().toLowerCase(); }));
  lines.forEach(function (line) {
    const parts = line.split(/[;,\t]\s*/).map(function (p) { return p.trim(); }).filter(Boolean);
    const nombre = parts.shift();
    if (!nombre) return;
    if (seen.has(nombre.toLowerCase())) {
      repetidos++;
      return;
    }
    seen.add(nombre.toLowerCase());
    v.equipos.push({
      id: uid(),
      nombre: nombre,
      ip: parts[0] || '',
      so: parts[1] || '',
      estado: estadoInicial,
      agregado: nowISO()
    });
    agregados++;
  });
  if (!agregados) {
    flashMsg(repetidos ? 'Todos los equipos ya existen en el inventario' : 'No se reconoció ninguna línea');
    return;
  }
  v.actualizado = nowISO();
  persist();
  $('#bulkTextarea').value = '';
  renderEquipos(v);
  renderList();
  flashMsg(agregados + ' equipo(s) agregados' + (repetidos ? ', ' + repetidos + ' duplicado(s) omitidos' : ''));
}

function bulkUpdateEquipos(v) {
  const lines = $('#updTextarea').value.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) {
    return l && !l.startsWith('#');
  });
  if (!lines.length) {
    flashMsg('Pega al menos una línea con nombres de equipos');
    return;
  }
  const estado = $('#updEstado').value || 'apagado';
  state.lastEqEstado = estado;
  let actualizados = 0, noEncontrados = 0, repetidos = 0;
  const updated = new Set();
  lines.forEach(function (line) {
    const parts = line.split(/[;,\t]\s*/).map(function (p) { return p.trim(); }).filter(Boolean);
    const nombre = parts[0];
    const ip = parts[1] || '';
    if (!nombre) return;
    let eq = v.equipos.find(function (e) { return e.nombre.trim().toLowerCase() === nombre.toLowerCase(); });
    if (!eq && ip) {
      eq = v.equipos.find(function (e) { return (e.ip || '').toLowerCase() === ip.toLowerCase(); });
    }
    if (!eq) {
      noEncontrados++;
      return;
    }
    if (updated.has(eq.id)) {
      repetidos++;
      return;
    }
    updated.add(eq.id);
    eq.estado = estado;
    eq.actualizado = nowISO();
    actualizados++;
  });
  if (!actualizados) {
    flashMsg(noEncontrados ? 'Ningún equipo coincidió con los nombres del lote' : 'No se reconoció ninguna línea');
    return;
  }
  v.actualizado = nowISO();
  persist();
  $('#updTextarea').value = '';
  renderEquipos(v);
  renderList();
  flashMsg(actualizados + ' equipo(s) actualizados a "' + estadoLabel(ESTADOS_EQ, estado) + '"' +
    (noEncontrados ? ', ' + noEncontrados + ' no encontrado(s)' : '') +
    (repetidos ? ', ' + repetidos + ' duplicado(s) omitidos' : ''));
}

function resetEqForm() {
  state.editingEqId = null;
  $('#eqForm').reset();
  $('#eqEstado').value = state.lastEqEstado;
  $('#eqSubmit').textContent = 'Agregar';
  $('#eqCancel').hidden = true;
}

function editEquipo(v, id) {
  const eq = v.equipos.find(function (e) { return e.id === id; });
  if (!eq) return;
  state.editingEqId = id;
  $('#eqNombre').value = eq.nombre || '';
  $('#eqIp').value = eq.ip || '';
  $('#eqSo').value = eq.so || '';
  $('#eqEstado').value = eq.estado || 'apagado';
  $('#eqSubmit').textContent = 'Guardar cambios';
  $('#eqCancel').hidden = false;
  $('#eqNombre').focus();
}

/* ---------------- Modal ---------------- */

function openVulnModal(v) {
  modalLastFocus = document.activeElement;
  state.editingVulnId = v ? v.id : null;
  $('#modalTitle').textContent = v ? 'Editar vulnerabilidad' : 'Nueva vulnerabilidad';
  $('#modalSave').textContent = v ? 'Guardar cambios' : 'Crear';
  $('#fTitulo').value = v ? (v.titulo || '') : '';
  $('#fSeveridad').value = v ? (v.severidad || 'media') : 'media';
  $('#fEstado').value = v ? (v.estado || 'abierta') : 'abierta';
  $('#fResponsable').value = v ? (v.responsable || '') : '';
  $('#fFecha').value = v ? (v.fecha_deteccion || '') : hoyISO();
  $('#fDescripcion').value = v ? (v.descripcion || '') : '';
  $('#modalOverlay').hidden = false;
  $('#fTitulo').focus();
}

function closeVulnModal() {
  $('#modalOverlay').hidden = true;
  state.editingVulnId = null;
  if (modalLastFocus && typeof modalLastFocus.focus === 'function') {
    modalLastFocus.focus();
  }
}

function saveVulnFromForm() {
  const titulo = $('#fTitulo').value.trim();
  if (!titulo) {
    flashMsg('El título es obligatorio');
    $('#fTitulo').focus();
    return;
  }
  const v = state.editingVulnId ? getSelected() : newVuln();
  if (!v) return;
  v.titulo = titulo;
  v.severidad = $('#fSeveridad').value;
  v.estado = $('#fEstado').value;
  v.responsable = $('#fResponsable').value.trim();
  v.fecha_deteccion = $('#fFecha').value || hoyISO();
  v.descripcion = $('#fDescripcion').value.trim();
  v.actualizado = nowISO();

  const creando = !state.editingVulnId;
  if (creando) {
    state.data.vulnerabilidades.push(v);
  }
  persist();
  closeVulnModal();
  renderList();
  selectVuln(v.id);
  flashMsg(creando ? 'Vulnerabilidad creada' : 'Cambios guardados');
}

/* ---------------- Archivos ---------------- */

async function saveToFile() {
  try {
    const res = await Storage.saveToFile(state.data, state.fileHandle);
    state.fileHandle = res.handle;
    state.fileName = res.name;
    state.dirty = false;
    updateSaveStatus();
    flashMsg('Datos guardados en ' + res.name);
  } catch (err) {
    if (err && err.name !== 'AbortError') {
      alert('No se pudo guardar el archivo: ' + err.message);
    }
  }
}

async function handleFileInput(e) {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  try {
    const data = await Storage.parseFile(file);
    if (state.data.vulnerabilidades.length &&
        !confirm('¿Reemplazar los datos actuales con el contenido de "' + file.name + '"?')) {
      return;
    }
    state.data = sanitizeData(data);
    state.fileHandle = null;
    state.fileName = file.name;
    state.dirty = false;
    state.selectedId = null;
    Storage.save(state.data);
    updateSaveStatus();
    renderList();
    renderDetail();
    updateSaveStatus();
    flashMsg('Archivo cargado: ' + file.name);
    if (state.data.vulnerabilidades.length) selectVuln(state.data.vulnerabilidades[0].id);
  } catch (err) {
    alert('Error al abrir el archivo: ' + err.message);
  }
}

/* ---------------- Eventos ---------------- */

function bindEvents() {
  $('#btnNew').addEventListener('click', function () { openVulnModal(null); });
  $('#btnOpen').addEventListener('click', function () { $('#fileInput').click(); });
  $('#btnSave').addEventListener('click', saveToFile);
  $('#fileInput').addEventListener('change', handleFileInput);
  $('#searchInput').addEventListener('input', renderList);
  $('#btnSummary').addEventListener('click', function () {
    if ($('#summaryView').hidden) {
      showSummary();
    } else {
      showDetailView();
    }
  });

  $('#sumBody').addEventListener('click', function (e) {
    const tr = e.target.closest('tr[data-id]');
    if (tr) selectVuln(tr.dataset.id);
  });

  $('#eqStateBody').addEventListener('click', function (e) {
    const tr = e.target.closest('tr[data-id]');
    if (tr) selectVuln(tr.dataset.id);
  });

  $('#vulnList').addEventListener('click', function (e) {
    const li = e.target.closest('.vuln-item');
    if (li) selectVuln(li.dataset.id);
  });

  $('#vulnList').addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const li = e.target.closest('.vuln-item');
    if (li) {
      e.preventDefault();
      selectVuln(li.dataset.id);
    }
  });

  function rowKeyNav(container) {
    container.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const tr = e.target.closest('tr[data-id]');
      if (tr) {
        e.preventDefault();
        selectVuln(tr.dataset.id);
      }
    });
  }
  rowKeyNav($('#sumBody'));
  rowKeyNav($('#eqStateBody'));

  $('#vulnEstado').addEventListener('change', function () {
    const v = getSelected();
    if (!v) return;
    v.estado = this.value;
    v.actualizado = nowISO();
    persist();
    renderList();
  });

  $('#btnEditVuln').addEventListener('click', function () {
    const v = getSelected();
    if (v) openVulnModal(v);
  });

  $('#btnDeleteVuln').addEventListener('click', function () {
    const v = getSelected();
    if (!v) return;
    if (!confirm('¿Eliminar la vulnerabilidad "' + (v.titulo || 'Sin título') + '" con su diagrama y equipos?')) return;
    state.data.vulnerabilidades = state.data.vulnerabilidades.filter(function (x) { return x.id !== v.id; });
    state.selectedId = null;
    persist();
    renderList();
    renderDetail();
    flashMsg('Vulnerabilidad eliminada');
  });

  $('#modalClose').addEventListener('click', closeVulnModal);
  $('#modalCancel').addEventListener('click', closeVulnModal);
  $('#modalOverlay').addEventListener('click', function (e) {
    if (e.target === this) closeVulnModal();
  });
  $('#vulnForm').addEventListener('submit', function (e) {
    e.preventDefault();
    saveVulnFromForm();
  });

  $('#eqForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const v = getSelected();
    if (!v) return;
    const nombre = $('#eqNombre').value.trim();
    if (!nombre) {
      flashMsg('El nombre del equipo es obligatorio');
      $('#eqNombre').focus();
      return;
    }
    if (state.editingEqId) {
      const eq = v.equipos.find(function (x) { return x.id === state.editingEqId; });
      if (eq) {
        eq.nombre = nombre;
        eq.ip = $('#eqIp').value.trim();
        eq.so = $('#eqSo').value.trim();
        eq.estado = $('#eqEstado').value;
        eq.actualizado = nowISO();
      }
    } else {
      v.equipos.push({
        id: uid(),
        nombre: nombre,
        ip: $('#eqIp').value.trim(),
        so: $('#eqSo').value.trim(),
        estado: $('#eqEstado').value,
        agregado: nowISO()
      });
    }
    v.actualizado = nowISO();
    persist();
    state.lastEqEstado = $('#eqEstado').value;
    const editando = !!state.editingEqId;
    resetEqForm();
    renderEquipos(v);
    renderList();
    flashMsg(editando ? 'Equipo actualizado' : 'Equipo agregado');
  });

  $('#eqCancel').addEventListener('click', resetEqForm);

  $('#btnBulkAdd').addEventListener('click', function () {
    const v = getSelected();
    if (v) bulkAddEquipos(v);
  });

  $('#btnBulkUpd').addEventListener('click', function () {
    const v = getSelected();
    if (v) bulkUpdateEquipos(v);
  });

  $('#eqSelectAll').addEventListener('change', function () {
    const v = getSelected();
    if (!v) return;
    if (this.checked) {
      v.equipos.forEach(function (e) { state.selectedEqs.add(e.id); });
    } else {
      state.selectedEqs.clear();
    }
    renderEquipos(v);
  });

  $('#btnBulkEstado').addEventListener('click', function () {
    const v = getSelected();
    if (!v) return;
    const ids = selectedEqIds(v);
    if (!ids.length) {
      flashMsg('Selecciona al menos un equipo');
      return;
    }
    const nuevo = $('#eqBulkEstado').value;
    v.equipos.forEach(function (e) {
      if (ids.includes(e.id)) {
        e.estado = nuevo;
        e.actualizado = nowISO();
      }
    });
    v.actualizado = nowISO();
    persist();
    renderEquipos(v);
    renderList();
    flashMsg('Estado aplicado a ' + ids.length + ' equipo(s)');
  });

  $('#btnBulkDelete').addEventListener('click', function () {
    const v = getSelected();
    if (!v) return;
    const ids = selectedEqIds(v);
    if (!ids.length) {
      flashMsg('Selecciona al menos un equipo');
      return;
    }
    if (!confirm('¿Eliminar ' + ids.length + ' equipo(s) del inventario?')) return;
    v.equipos = v.equipos.filter(function (e) { return !ids.includes(e.id); });
    ids.forEach(function (id) { state.selectedEqs.delete(id); });
    v.actualizado = nowISO();
    persist();
    renderEquipos(v);
    renderList();
    flashMsg(ids.length + ' equipo(s) eliminados');
  });

  $('#btnBulkClear').addEventListener('click', function () {
    state.selectedEqs.clear();
    const v = getSelected();
    if (v) renderEquipos(v);
  });

  $('#eqSearch').addEventListener('input', function () {
    state.eqFilter = this.value.trim().toLowerCase();
    const v = getSelected();
    if (v) renderEquipos(v);
  });

  $('#btnSelectFiltered').addEventListener('click', function () {
    const v = getSelected();
    if (!v) return;
    const ids = filteredEquipos(v).map(function (e) { return e.id; });
    if (!ids.length) {
      flashMsg('No hay coincidencias para seleccionar');
      return;
    }
    ids.forEach(function (id) { state.selectedEqs.add(id); });
    renderEquipos(v);
    flashMsg(ids.length + ' equipo(s) seleccionados');
  });

  $('#eqBody').addEventListener('click', function (e) {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const v = getSelected();
    if (!v) return;
    if (btn.dataset.action === 'edit') {
      editEquipo(v, btn.dataset.id);
    } else if (btn.dataset.action === 'del') {
      const eq = v.equipos.find(function (x) { return x.id === btn.dataset.id; });
      if (eq && confirm('¿Quitar el equipo "' + eq.nombre + '" del inventario?')) {
        v.equipos = v.equipos.filter(function (x) { return x.id !== btn.dataset.id; });
        v.actualizado = nowISO();
        persist();
        if (state.editingEqId === btn.dataset.id) resetEqForm();
        renderEquipos(v);
        renderList();
        flashMsg('Equipo eliminado');
      }
    }
  });

  $('#eqBody').addEventListener('change', function (e) {
    const v = getSelected();
    if (!v) return;
    if (e.target.classList.contains('eq-chk')) {
      if (e.target.checked) state.selectedEqs.add(e.target.dataset.id);
      else state.selectedEqs.delete(e.target.dataset.id);
      renderBulkBar(v);
      return;
    }
    if (!e.target.classList.contains('eq-estado')) return;
    const eq = v.equipos.find(function (x) { return x.id === e.target.dataset.id; });
    if (eq) {
      eq.estado = e.target.value;
      eq.actualizado = nowISO();
      v.actualizado = nowISO();
      persist();
      renderList();
    }
  });

  window.addEventListener('keydown', function (e) {
    const overlay = $('#modalOverlay');
    if (!overlay.hidden) {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeVulnModal();
        return;
      }
      if (e.key === 'Tab') {
        const focusables = overlay.querySelectorAll('button:not([hidden]), input:not([hidden]), select:not([hidden]), textarea:not([hidden]), [href], [tabindex]:not([tabindex="-1"])');
        const list = Array.from(focusables).filter(function (el) { return !el.disabled; });
        if (!list.length) return;
        const first = list[0];
        const last = list[list.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      saveToFile();
    }
  });
}

function init() {
  const saved = Storage.load();
  if (saved && Array.isArray(saved.vulnerabilidades)) {
    state.data = sanitizeData(saved);
  }
  const legend = $('#ganttLegend');
  legend.innerHTML = ETAPAS.map(function (e) {
    return '<span class="lg"><i style="background:' + e.color + '"></i>' + e.nombre + '</span>';
  }).join('');
  $('#sumLegend').innerHTML = ['critica', 'alta', 'media', 'baja'].map(function (k) {
    return '<span class="lg"><i style="background:' + SEV[k].color + '"></i>' + SEV[k].label + '</span>';
  }).join('');
  $('#eqStateLegend').innerHTML = ESTADOS_EQ.map(function (e) {
    return '<span class="lg"><i style="background:' + ESTADOS_EQ_COLOR[e[0]] + '"></i>' + e[1] + '</span>';
  }).join('');

  bindEvents();
  renderList();
  updateSaveStatus();
  if (state.data.vulnerabilidades.length) {
    selectVuln(state.data.vulnerabilidades[0].id);
  } else {
    showEmpty();
  }
}

document.addEventListener('DOMContentLoaded', init);
