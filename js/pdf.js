/* Generador mínimo de PDF (A4) en JS puro, sin librerías externas. */
const PDFDoc = (() => {
  const PW = 595.28;
  const PH = 841.89;

  const W_HEL = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    278,278,355,556,556,889,667,191,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,278,278,584,584,584,556,
    1015,667,667,722,722,667,611,778,722,278,500,667,556,833,722,778,667,778,722,667,611,722,667,944,667,667,611,278,278,278,469,556,
    333,556,556,500,556,556,278,556,556,222,222,500,222,833,556,556,556,556,333,500,278,556,500,722,500,500,500,334,260,334,584];
  const W_HEL_B = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    278,333,474,556,556,889,722,238,333,333,389,584,278,333,278,278,556,556,556,556,556,556,556,556,556,556,333,333,584,584,584,611,
    975,722,722,722,722,667,611,778,722,278,556,722,611,833,722,778,667,778,722,667,611,722,667,944,667,667,611,333,278,333,584,556,
    333,556,611,556,611,556,333,611,611,278,278,556,278,889,611,611,611,611,389,556,333,611,556,778,556,556,500,389,280,389,584];

  const BASE = { 224:97,225:97,226:97,227:97,228:97,229:97,231:99,232:101,233:101,234:101,235:101,
    236:105,237:105,238:105,239:105,241:110,242:111,243:111,244:111,245:111,246:111,248:111,
    249:117,250:117,251:117,252:117,253:121,255:121,160:32,161:33,162:99,177:45 };

  function latin1(s) {
    return String(s)
      .replace(/[\u2018\u2019\u201a]/g, "'")
      .replace(/[\u201c\u201d\u201e]/g, '"')
      .replace(/\u2013/g, '-')
      .replace(/\u2014/g, '-')
      .replace(/\u2026/g, '...')
      .replace(/\u2022/g, '*')
      .replace(/\u00b7/g, '*')
      .replace(/[^\x00-\xFF]/g, '?');
  }

  function escPdf(s) {
    return latin1(s).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  }

  function charW(c, bold) {
    const code = c.charCodeAt(0);
    const t = bold ? W_HEL_B : W_HEL;
    if (code >= 32 && code <= 126) return t[code];
    if (code >= 160 && code <= 255) return t[BASE[code] || code] || 556;
    return 556;
  }

  function strW(str, font, size) {
    const bold = font === 'F2';
    let w = 0;
    for (let i = 0; i < str.length; i++) w += charW(str.charAt(i), bold);
    return w * size / 1000;
  }

  function Doc() {
    this.margin = 28;
    this.pages = [[]];
    this.y = this.margin;
    this.f = 'F1';
    this.s = 10;
    this.color = '0.13 0.16 0.22';
  }

  Doc.prototype.op = function (t) {
    this.pages[this.pages.length - 1].push(t);
  };

  Doc.prototype.newPage = function () {
    this.pages.push([]);
    this.y = this.margin;
  };

  Doc.prototype.bottomLimit = function () { return PH - 64; };

  Doc.prototype.ensure = function (h) {
    if (this.y + h > this.bottomLimit()) this.newPage();
  };

  Doc.prototype.text = function (str, x, top, opts) {
    opts = opts || {};
    const f = opts.font || this.f;
    const s = opts.size || this.s;
    const c = opts.color || this.color;
    const baseline = PH - top - s * 0.78;
    this.op('BT /' + f + ' ' + s + ' Tf ' + c + ' rg ' + x.toFixed(2) + ' ' + baseline.toFixed(2) + ' Td (' + escPdf(str) + ') Tj ET');
  };

  Doc.prototype.w = function (str, font, size) {
    return strW(str, font || this.f, size || this.s);
  };

  Doc.prototype.rect = function (x, top, w, h, fill, stroke) {
    const b = PH - top - h;
    let s = 'q ';
    if (fill) s += fill + ' rg ' + x.toFixed(2) + ' ' + b.toFixed(2) + ' ' + w.toFixed(2) + ' ' + h.toFixed(2) + ' re f ';
    if (stroke) s += stroke + ' RG 0.6 w ' + x.toFixed(2) + ' ' + b.toFixed(2) + ' ' + w.toFixed(2) + ' ' + h.toFixed(2) + ' re S ';
    this.op(s + 'Q');
  };

  Doc.prototype.hline = function (top, x1, x2, color, w) {
    const y = PH - top;
    this.op('q ' + (color || '0.85 0.87 0.9') + ' RG ' + (w || 0.6) + ' w ' + x1.toFixed(2) + ' ' + y.toFixed(2) + ' m ' + x2.toFixed(2) + ' ' + y.toFixed(2) + ' l S Q');
  };

  Doc.prototype.wrap = function (str, maxW, font, size) {
    font = font || this.f;
    size = size || this.s;
    const words = String(str).split(/\s+/);
    const lines = [];
    let cur = '';
    words.forEach(function (word) {
      const test = cur ? cur + ' ' + word : word;
      if (strW(test, font, size) <= maxW || !cur) {
        cur = test;
      } else {
        lines.push(cur);
        cur = word;
      }
    });
    if (cur) lines.push(cur);
    return lines;
  };

  Doc.prototype.para = function (str, x, maxW, opts) {
    opts = opts || {};
    const f = opts.font || this.f;
    const s = opts.size || this.s;
    const c = opts.color || this.color;
    const lh = opts.lineH || s * 1.45;
    const lines = this.wrap(str, maxW, f, s);
    for (let i = 0; i < lines.length; i++) {
      this.ensure(lh);
      this.text(lines[i], x, this.y, { font: f, size: s, color: c });
      this.y += lh;
    }
    this.y += opts.gapAfter != null ? opts.gapAfter : 6;
  };

  Doc.prototype.table = function (headers, widths, rows, opts) {
    opts = opts || {};
    const self = this;
    const x0 = this.margin;
    const totalW = widths.reduce(function (a, b) { return a + b; }, 0);
    const pad = 5;
    const lineH = opts.lineH || 10.5;
    const hS = opts.headSize || 7;
    const cS = opts.size || 9;
    const headBg = opts.headBg || '0.06 0.09 0.16';
    const headFg = opts.headFg || '1 1 1';
    const zebra = opts.zebra || '0.945 0.955 0.97';
    const headH = 17;

    if (!rows.length) {
      rows = [headers.map(function (h, i) { return i === 0 ? 'Sin datos' : ''; })];
    }

    function cellObj(c) {
      return (c && typeof c === 'object') ? c : { t: c };
    }
    function linesFor(cells) {
      return cells.map(function (c, i) {
        const p = cellObj(c);
        return self.wrap(String(p.t == null ? '' : p.t), widths[i] - pad * 2, p.b ? 'F2' : 'F1', cS);
      });
    }
    function rowH(lns) {
      let m = 1;
      lns.forEach(function (l) { m = Math.max(m, l.length); });
      return Math.max(m * lineH + pad * 2, 17);
    }
    function headerBand() {
      self.rect(x0, self.y, totalW, headH, headBg);
      let x = x0;
      headers.forEach(function (h, i) {
        self.text(String(h).toUpperCase(), x + pad, self.y + (headH - hS) / 2, { font: 'F2', size: hS, color: headFg });
        x += widths[i];
      });
      self.y += headH;
    }

    if (opts.keepTogether) {
      const blockHeight = headH + rows.reduce(function (sum, cells) {
        return sum + rowH(linesFor(cells));
      }, 0) + 10;
      if (blockHeight <= self.bottomLimit() - self.margin) self.ensure(blockHeight);
    }

    let needHeader = true;
    rows.forEach(function (cells, ri) {
      const lns = linesFor(cells);
      const rh = rowH(lns);
      if (needHeader) {
        self.ensure(headH + rh);
        headerBand();
        needHeader = false;
      } else if (self.y + rh > self.bottomLimit()) {
        self.newPage();
        headerBand();
      }
      if (ri % 2 === 1) self.rect(x0, self.y, totalW, rh, zebra);
      let x = x0;
      lns.forEach(function (lines, i) {
        const cell = cellObj(cells[i]);
        lines.forEach(function (ln, li) {
          self.text(ln, x + pad, self.y + pad + li * lineH, { font: cell.b ? 'F2' : 'F1', size: cS, color: cell.c });
        });
        x += widths[i];
      });
      self.y += rh;
      self.hline(self.y, x0, x0 + totalW);
    });
    this.y += 10;
  };

  Doc.prototype.save = function (name) {
    const n = this.pages.length;
    const idF1 = 3 + n;
    const idF2 = idF1 + 1;
    const idC0 = idF2 + 1;
    const kids = [];
    for (let i = 0; i < n; i++) kids.push((3 + i) + ' 0 R');

    const parts = ['%PDF-1.4\n'];
    let pos = parts[0].length;
    const offsets = {};
    function obj(num, body) {
      offsets[num] = pos;
      const s = num + ' 0 obj\n' + body + '\nendobj\n';
      parts.push(s);
      pos += s.length;
    }

    obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
    obj(2, '<< /Type /Pages /Kids [' + kids.join(' ') + '] /Count ' + n + ' >>');
    for (let i = 0; i < n; i++) {
      obj(3 + i, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + PW + ' ' + PH + '] /Resources << /Font << /F1 ' + idF1 + ' 0 R /F2 ' + idF2 + ' 0 R >> >> /Contents ' + (idC0 + i) + ' 0 R >>');
    }
    obj(idF1, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    obj(idF2, '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');

    for (let i = 0; i < n; i++) {
      const foot = '\nq 0.8 0.82 0.85 RG 0.5 w ' + this.margin + ' 40 m ' + (PW - this.margin) + ' 40 l S Q' +
        '\nBT /F1 7.5 Tf 0.45 0.47 0.5 rg ' + this.margin + ' 30 Td (VulnGantt \\227 Informe Ejecutivo de Vulnerabilidades) Tj ET' +
        '\nBT /F1 7.5 Tf 0.45 0.47 0.5 rg ' + (PW - this.margin - 52).toFixed(2) + ' 30 Td (P\\341gina ' + (i + 1) + ' de ' + n + ') Tj ET';
      const stream = this.pages[i].join('\n') + foot;
      obj(idC0 + i, '<< /Length ' + stream.length + ' >>\nstream\n' + stream + '\nendstream');
    }

    const xrefPos = pos;
    let x = 'xref\n0 ' + (idC0 + n) + '\n0000000000 65535 f \n';
    for (let num = 1; num < idC0 + n; num++) {
      x += String(offsets[num]).padStart(10, '0') + ' 00000 n \n';
    }
    x += 'trailer\n<< /Size ' + (idC0 + n) + ' /Root 1 0 R >>\nstartxref\n' + xrefPos + '\n%%EOF';
    parts.push(x);

    const str = parts.join('');
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i) & 0xFF;
    const blob = new Blob([bytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  };

  return { Doc: Doc, PW: PW, PH: PH };
})();
