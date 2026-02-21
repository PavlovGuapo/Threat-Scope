/* ═══════════════════════════════════════════════════════════
   THREAT-SCOPE — report.js
   Generador de reportes Word (.docx) por IP
   Requiere: window.docx (unpkg CDN), Chart.js (ya cargado)
   ═══════════════════════════════════════════════════════════ */

"use strict";

const R = {
  C_BG:       "1D1D1B",
  C_RED:      "BE1622",
  C_GREEN:    "95C11F",
  C_ORANGE:   "E85D04",
  C_YELLOW:   "F4A261",
  C_BLUE:     "4A9EDA",
  C_PURPLE:   "C77DFF",
  C_WHITE:    "FFFFFF",
  C_GRAY:     "888885",
  C_DARK:     "2E2E2C",
  C_LIGHT:    "F4F4F4",
  C_BORDER:   "3A3A38",

  SEV: { critical:"BE1622", high:"E85D04", medium:"F4A261", low:"95C11F", info:"4A9EDA" },
  SEV_BG: { critical:"FAE5E7", high:"FDE8DC", medium:"FEF3E8", low:"EDF7DB", info:"DFF0FA" },
  SEV_ES: { critical:"CRÍTICA", high:"ALTA", medium:"MEDIA", low:"BAJA", info:"INFO" },

  ST: { pending:"888885", exploited:"BE1622", patched:"95C11F", false_positive:"C77DFF" },
  ST_ES: { pending:"Pendiente", exploited:"Explotada", patched:"Parcheada", false_positive:"Falso Positivo" },
  ST_BG: { pending:"F0F0F0", exploited:"FAE5E7", patched:"EDF7DB", false_positive:"F3E8FF" },

  PAGE_W: 11906,
  PAGE_H: 16838,
  MARGIN: 1134,
  get CONTENT_W() { return this.PAGE_W - this.MARGIN * 2; },
};

function cHex(val, fallback = "FFFFFF") {
  if (!val) return fallback;
  let s = String(val).replace("#", "").trim().toUpperCase();
  if (s === "AUTO") return "auto";
  if (/^[0-9A-F]{6}$/i.test(s)) return s;
  return fallback;
}

function d() { return window.docx; }

function txt(text, opts = {}) {
  const runOpts = { text: String(text || "") };
  for (const [k, v] of Object.entries(opts)) {
    if (v !== undefined) runOpts[k] = v;
  }
  if (runOpts.color) runOpts.color = cHex(runOpts.color);
  return new (d().TextRun)(runOpts);
}

function para(children, opts = {}) {
  if (typeof children === "string" || typeof children === "number") children = [txt(String(children))];
  if (!Array.isArray(children)) children = [children];
  return new (d().Paragraph)({ children, ...opts });
}

function heading1(text) {
  return new (d().Paragraph)({
    heading: "heading1",
    children: [txt(text, { font: "Arial", size: 32, bold: true, color: R.C_BG })],
    spacing: { before: 360, after: 200 },
    border: { bottom: { style: "single", size: 8, color: cHex(R.C_RED), space: 6 } }
  });
}

function spacer(lines = 1) {
  return Array.from({ length: lines }, () => para("", { spacing: { after: 0 } }));
}

function pageBreak() {
  return para([new (d().PageBreak)()]);
}

function hRule(color = R.C_RED) {
  return para("", {
    border: { bottom: { style: "single", size: 6, color: cHex(color), space: 2 } },
    spacing: { before: 60, after: 60 }
  });
}

const cellMargins = { top: 150, bottom: 150, left: 120, right: 120 };

function tableCell(children, opts = {}) {
  if (children === undefined || children === null) children = ["—"];
  if (typeof children === "string" || typeof children === "number") children = [para(String(children))];
  if (!Array.isArray(children)) children = [children];

  const b1 = { style: "single", size: 1, color: cHex(R.C_BORDER) };
  const safeBorders = { top: b1, bottom: b1, left: b1, right: b1 };

  const cellOpts = { borders: safeBorders, margins: cellMargins, children };
  for (const [k, v] of Object.entries(opts)) {
    if (v !== undefined) cellOpts[k] = v;
  }
  return new (d().TableCell)(cellOpts);
}

function headerCell(text, bgColor = R.C_BG, textColor = R.C_WHITE, width = 1200) {
  return tableCell([
    para([txt(text, { font: "Arial", size: 18, bold: true, color: cHex(textColor) })],
      { alignment: "center" })
  ], {
    width: { size: width, type: "dxa" },
    shading: { fill: cHex(bgColor), type: "clear" },
    verticalAlign: "center"
  });
}

function dataCell(content, opts = {}, textOpts = {}) {
  if (content === undefined || content === null) content = "—";
  if (typeof content !== "string" && !Array.isArray(content) && typeof content !== "object") content = String(content);

  let children = [];
  if (typeof content === "string") {
    if (content.includes("\n")) {
      const lines = content.split("\n");
      const runs = lines.map((line, idx) => {
        const r = { text: line, ...textOpts };
        if (idx > 0) r.break = 1;
        if (r.color) r.color = cHex(r.color);
        return new (d().TextRun)(r);
      });
      children = [new (d().Paragraph)({ children: runs, alignment: opts.alignment || "left" })];
    } else {
      children = [para([txt(content, { font: "Arial", size: 18, ...textOpts })],
        { alignment: opts.alignment || "left" })];
    }
  } else if (Array.isArray(content)) {
    children = content;
  }

  const cellOpts = {
    width: { size: opts.width || 1200, type: "dxa" },
    shading: { fill: cHex(opts.bg || R.C_WHITE), type: "clear" },
    verticalAlign: "top"
  };
  if (opts.columnSpan) cellOpts.columnSpan = opts.columnSpan;
  if (opts.rowSpan) cellOpts.rowSpan = opts.rowSpan;

  return tableCell(children, cellOpts);
}

function canvasToBytes(canvas) {
  try {
    const b64 = canvas.toDataURL("image/png").split(",")[1];
    const raw = atob(b64);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
  } catch { return null; }
}

async function urlToBytes(url) {
  try {
    const res  = await fetch(url);
    const blob = await res.blob();
    return new Uint8Array(await blob.arrayBuffer());
  } catch { return null; }
}

function imageRun(bytes, widthPx, heightPx) {
  if (!bytes) return null;
  return new (d().ImageRun)({
    data: bytes,
    transformation: { width: widthPx, height: heightPx },
    type: "png"
  });
}

function getIpChartImages(panel) {
  const imgs = {};
  const canvases = {
    port:        panel.querySelector(".chart-by-port"),
    dist:        panel.querySelector(".chart-dist"),
    status:      panel.querySelector(".chart-status"),
    remediation: panel.querySelector(".chart-remediation")
  };
  for (const [key, canvas] of Object.entries(canvases)) {
    if (canvas) imgs[key] = canvasToBytes(canvas);
  }
  return imgs;
}

function buildCoverPage(ipData) {
  const { ip, organization, description, scanner, scanDate, vulns } = ipData;
  const sev = countBySev(vulns);
  const today = new Date().toLocaleDateString("es-MX", { year:"numeric", month:"long", day:"numeric" });

  const coverTable = new (d().Table)({
    width: { size: R.CONTENT_W, type: "dxa" },
    columnWidths: [R.CONTENT_W],
    rows: [
      new (d().TableRow)({
        children: [tableCell([
          para([
            txt("THREAT-SCOPE", { font:"Arial", size: 52, bold: true, color: cHex(R.C_RED), allCaps: true }),
          ], { alignment: "center", spacing: { before: 300, after: 80 } }),
          para([
            txt("VULNERABILITY ASSESSMENT REPORT", { font:"Arial", size: 22, bold: true, color: cHex("AAAAAA"), allCaps: true }),
          ], { alignment: "center", spacing: { after: 300 } }),
        ], {
          width: { size: R.CONTENT_W, type: "dxa" },
          shading: { fill: cHex(R.C_BG), type: "clear" }
        })]
      })
    ]
  });

  const infoTable = new (d().Table)({
    width: { size: R.CONTENT_W, type: "dxa" },
    columnWidths: [2400, R.CONTENT_W - 2400],
    rows: [
      ["DIRECCIÓN IP", ip],
      ["ORGANIZACIÓN", organization || "—"],
      ["DESCRIPCIÓN", description || "—"],
      ["SCANNER(S)", scanner],
      ["FECHA DE ESCANEO", scanDate || "—"],
      ["FECHA DE REPORTE", today],
    ].map(([label, value]) =>
      new (d().TableRow)({
        children: [
          tableCell([para([txt(label, { font:"Arial", size:19, bold:true, color: cHex(R.C_WHITE) })], { alignment: "right" })],
            { width:{size:2400,type:"dxa"}, shading:{fill:cHex(R.C_DARK),type:"clear"} }),
          tableCell([para([txt(String(value || "—"), { font:"Arial", size:19, color: cHex(R.C_BG) })], { alignment: "left" })],
            { width:{size:R.CONTENT_W-2400,type:"dxa"}, shading:{fill:cHex(R.C_LIGHT),type:"clear"} }),
        ]
      })
    )
  });

  const statsTable = buildStatsSummaryTable(sev, countBySt(vulns));

  return [
    coverTable,
    ...spacer(2),
    infoTable,
    ...spacer(2),
    hRule(),
    para([txt("RESUMEN DE HALLAZGOS", { font:"Arial", size:22, bold:true, color: cHex(R.C_BG), allCaps:true })],
      { alignment: "center", spacing:{before:200,after:160} }),
    statsTable,
    pageBreak()
  ];
}

function buildStatsSummaryTable(sev, st) {
  const sevCols = [
    { label:"CRÍTICAS",   value: sev.critical, bg: R.SEV_BG.critical, color: R.SEV.critical },
    { label:"ALTAS",      value: sev.high,     bg: R.SEV_BG.high,     color: R.SEV.high },
    { label:"MEDIAS",     value: sev.medium,   bg: R.SEV_BG.medium,   color: R.SEV.medium },
    { label:"BAJAS",      value: sev.low,      bg: R.SEV_BG.low,      color: R.SEV.low },
    { label:"INFO",       value: sev.info,     bg: R.SEV_BG.info,     color: R.SEV.info },
    { label:"EXPLOTADAS", value: st.exploited, bg: "FAE5E7",          color: R.C_RED },
    { label:"PARCHEADAS", value: st.patched,   bg: "EDF7DB",          color: "4A7C10" },
    { label:"F.POSITIVOS",value: st.false_positive, bg: "F3E8FF",     color: "8B3FCF" },
  ];

  const colW = Math.floor(R.CONTENT_W / sevCols.length);
  return new (d().Table)({
    width: { size: R.CONTENT_W, type: "dxa" },
    columnWidths: sevCols.map(() => colW),
    rows: [
      new (d().TableRow)({
        children: sevCols.map(c => tableCell([
          para([txt(c.label, { font:"Arial", size:15, bold:true, color: cHex(c.color), allCaps:true })],
            { alignment: "center", spacing:{after:40} }),
          para([txt(String(c.value || 0), { font:"Arial", size:36, bold:true, color: cHex(c.color) })],
            { alignment: "center" })
        ], { width:{size:colW,type:"dxa"}, shading:{fill:cHex(c.bg),type:"clear"} }))
      })
    ]
  });
}

function buildChartsSection(chartImgs) {
  const items = [ heading1("GRÁFICAS Y VISUALIZACIONES") ];

  function chartBlock(key, label, w, h) {
    const bytes = chartImgs[key];
    if (!bytes) return [];
    const imgEl = imageRun(bytes, w, h);
    if (!imgEl) return [];
    return [
      para([txt(label.toUpperCase(), { font:"Arial", size:17, bold:true, color: cHex(R.C_GRAY), allCaps:true })],
        { alignment: "center", spacing:{before:200,after:80}, keepNext: true }),
      para([imgEl], { alignment: "center", spacing:{after:200} })
    ];
  }

  items.push(...chartBlock("dist", "Distribución por Criticidad", 350, 260));
  items.push(...chartBlock("status", "Estado de Vulnerabilidades", 450, 260));

  if (chartImgs.port) {
    const portImg = imageRun(chartImgs.port, 650, 300);
    if (portImg) {
      items.push(para([txt("VULNERABILIDADES POR PUERTO", { font:"Arial", size:17, bold:true, color: cHex(R.C_GRAY), allCaps:true })],
        { alignment: "center", spacing:{before:200,after:80}, keepNext: true }));
      items.push(para([portImg], { alignment: "center", spacing:{after:200} }));
    }
  }

  items.push(...chartBlock("remediation", "Progreso de Remediación", 450, 260));
  items.push(pageBreak());
  return items;
}

function sortVulns(vulns) {
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...vulns].sort((a, b) => {
    const sevA = sevOrder[a.severity] ?? 4;
    const sevB = sevOrder[b.severity] ?? 4;
    if (sevA !== sevB) return sevA - sevB;
    const cvssA = parseFloat(a.cvss) || 0;
    const cvssB = parseFloat(b.cvss) || 0;
    return cvssB - cvssA;
  });
}

function buildVulnTableSection(vulns) {
  const items = [
    heading1("TABLA RESUMEN DE VULNERABILIDADES"),
    para([txt(`Total de vulnerabilidades identificadas: ${vulns.length}`, {
      font:"Arial", size:20, color: cHex(R.C_BG)
    })], { spacing:{after:160} })
  ];

  const COLS = [
    { label:"#",         w: 400 },
    { label:"CVE / ID",  w: 1500 },
    { label:"NOMBRE",    w: 3000 },
    { label:"SEVERITY",  w: 900 },
    { label:"CVSS",      w: 600 },
    { label:"PUERTO",    w: 700 },
    { label:"ESTADO",    w: 1538 },
  ];
  const sumW = COLS.reduce((a,c)=>a+c.w,0);
  COLS[COLS.length-1].w += R.CONTENT_W - sumW;

  const sorted = sortVulns(vulns);

  const headerRow = new (d().TableRow)({
    tableHeader: true,
    children: COLS.map(c => headerCell(c.label, R.C_BG, R.C_WHITE, c.w))
  });

  const dataRows = sorted.map((v, i) => {
    const rowBg = i % 2 === 0 ? R.C_WHITE : "F8F8F8";
    const sevColor = R.SEV[v.severity] || R.C_GRAY;
    const sevBg    = R.SEV_BG[v.severity] || "F8F8F8";
    const stColor  = R.ST[v.status] || R.C_GRAY;
    const stBg     = R.ST_BG[v.status] || "F0F0F0";
    const cveText  = (v.cve || "—").split(",").map(c=>c.trim()).filter(Boolean).join("\n");
    
    return new (d().TableRow)({
      children: [
        dataCell(String(i+1), { bg:rowBg, width:COLS[0].w, alignment:"center" }, { bold:true }),
        dataCell(cveText, { bg:rowBg, width:COLS[1].w }, { size:16, color:"2E6DA4" }),
        dataCell(v.name ? v.name.substring(0,80) : "—", { bg:rowBg, width:COLS[2].w }, { size:17 }),
        dataCell(R.SEV_ES[v.severity]||v.severity||"—", { bg:sevBg, width:COLS[3].w, alignment:"center" },
          { bold:true, color:sevColor, size:16 }),
        dataCell(v.cvss ? String(v.cvss) : "—", { bg:rowBg, width:COLS[4].w, alignment:"center" },
          { color: sevColor, bold:!!v.cvss }),
        dataCell(v.port ? String(v.port) : "—", { bg:rowBg, width:COLS[5].w, alignment:"center" }),
        dataCell(R.ST_ES[v.status]||v.status||"—", { bg:stBg, width:COLS[6].w, alignment:"center" },
          { bold:true, color:stColor, size:16 }),
      ]
    });
  });

  items.push(new (d().Table)({
    width: { size: R.CONTENT_W, type: "dxa" },
    columnWidths: COLS.map(c=>c.w),
    rows: [headerRow, ...dataRows]
  }));

  items.push(pageBreak());
  return items;
}

async function buildVulnDetails(vulns, ipData) {
  const items = [heading1("DETALLE DE VULNERABILIDADES")];
  const sorted = sortVulns(vulns);

  for (let i = 0; i < sorted.length; i++) {
    const v = sorted[i];
    const sevColor = R.SEV[v.severity] || R.C_GRAY;
    const sevBg    = R.SEV_BG[v.severity] || "F8F8F8";
    const stColor  = R.ST[v.status] || R.C_GRAY;
    const stBg     = R.ST_BG[v.status] || "F0F0F0";
    const vName    = v.name ? v.name.substring(0,100) : "—";

    items.push(new (d().Table)({
      width: { size: R.CONTENT_W, type: "dxa" },
      columnWidths: [600, R.CONTENT_W - 1800, 600, 600],
      rows: [new (d().TableRow)({
        children: [
          headerCell(`${i+1}`, R.C_BG, R.C_WHITE, 600),
          tableCell([para([txt(vName, { font:"Arial", size:20, bold:true, color: cHex(R.C_BG) })])],
            { width:{size:R.CONTENT_W-1800,type:"dxa"}, shading:{fill:cHex("EFEFEF"),type:"clear"} }),
          tableCell([para([txt(R.SEV_ES[v.severity]||v.severity||"—", { font:"Arial", size:18, bold:true, color:cHex(sevColor) })],
            { alignment:"center" })],
            { width:{size:600,type:"dxa"}, shading:{fill:cHex(sevBg),type:"clear"}, verticalAlign:"center" }),
          tableCell([para([txt(R.ST_ES[v.status]||v.status||"—", { font:"Arial", size:16, bold:true, color:cHex(stColor) })],
            { alignment:"center" })],
            { width:{size:600,type:"dxa"}, shading:{fill:cHex(stBg),type:"clear"}, verticalAlign:"center" }),
        ]
      })]
    }));

    const cveText = (v.cve || "—").split(",").map(c=>c.trim()).filter(Boolean).join("\n");

    const metaCols = [
      ["CVE / ID",  cveText],
      ["CVSS",      v.cvss    ? String(v.cvss) : "—"],
      ["PUERTO",    v.port    ? `${v.port}${v.protocol?"/"+v.protocol:""}` : "—"],
      ["SCANNER",   v.scanner || "—"],
    ];
    const metaColW = Math.floor(R.CONTENT_W / metaCols.length);

    items.push(new (d().Table)({
      width: { size: R.CONTENT_W, type: "dxa" },
      columnWidths: metaCols.map(()=>metaColW),
      rows: [new (d().TableRow)({
        children: metaCols.map(([lbl,val]) =>
          tableCell([
            para([txt(lbl, { font:"Arial", size:15, bold:true, color:cHex(R.C_GRAY), allCaps:true })],
              { spacing:{after:40} }),
            ...(val.includes("\n") 
              ? [new (d().Paragraph)({ children: val.split("\n").map((line, idx) => new (d().TextRun)({ text: line, break: idx > 0 ? 1 : 0, font:"Arial", size:18, color:cHex(R.C_BG) })) })]
              : [para([txt(val, { font:"Arial", size:18, color:cHex(R.C_BG) })])])
          ], { width:{size:metaColW,type:"dxa"}, shading:{fill:cHex("FAFAFA"),type:"clear"} })
        )
      })]
    }));

    if (v.description) {
      items.push(para([txt("DESCRIPCIÓN", { font:"Arial", size:17, bold:true, color:cHex(R.C_GRAY), allCaps:true })],
        { spacing:{before:140,after:60}, keepNext: true }));
      const descParts = String(v.description).substring(0,1200).split("\n").filter(l=>l.trim());
      descParts.forEach(line => {
        items.push(para([txt(line.trim(), { font:"Arial", size:18, color:cHex("333333") })],
          { spacing:{after:60}, indent:{left:240} }));
      });
    }

    if (v.solution) {
      items.push(para([txt("SOLUCIÓN / MITIGACIÓN", { font:"Arial", size:17, bold:true, color:cHex(R.C_GRAY), allCaps:true })],
        { spacing:{before:120,after:60}, keepNext: true }));
      items.push(para([txt(String(v.solution).substring(0,800), { font:"Arial", size:18, color:cHex("333333") })],
        { spacing:{after:80}, indent:{left:240} }));
    }

    if (v.reference) {
      items.push(para([
        txt("REFERENCIA: ", { font:"Arial", size:16, bold:true, color:cHex(R.C_GRAY) }),
        txt(String(v.reference).substring(0,200), { font:"Arial", size:16, color:cHex("2E6DA4") })
      ], { spacing:{after:80} }));
    }

    const evidence = v.evidence || [];
    if (evidence.length > 0) {
      items.push(para([txt("EVIDENCIA FOTOGRÁFICA", { font:"Arial", size:17, bold:true, color:cHex(R.C_GRAY), allCaps:true })],
        { spacing:{before:120,after:80}, keepNext: true }));

      for (const ev of evidence) {
        if (!ev) continue;
        try {
          let bytes;
          if (ev.startsWith("data:")) {
            const b64 = ev.split(",")[1];
            const raw = atob(b64);
            bytes = new Uint8Array(raw.length);
            for (let j=0; j<raw.length; j++) bytes[j] = raw.charCodeAt(j);
          } else {
            bytes = await urlToBytes(`/evidence/${ev}`);
          }
          if (bytes) {
            const imgEl = new (d().ImageRun)({
              data: bytes,
              transformation: { width: 500, height: 320 },
              type: "png"
            });
            items.push(para([imgEl], {
              alignment: "left",
              spacing: { after: 80 }
            }));
          }
        } catch(e) { }
      }
    }

    items.push(hRule(i < sorted.length - 1 ? "DDDDDD" : R.C_RED));
    if (i < sorted.length - 1 && (i + 1) % 5 === 0) items.push(pageBreak());
  }

  return items;
}

function countBySev(vulns) {
  const c = {critical:0,high:0,medium:0,low:0,info:0};
  vulns.forEach(v=>{ if(v.severity && c[v.severity]!==undefined) c[v.severity]++; });
  return c;
}
function countBySt(vulns) {
  const c = {pending:0,exploited:0,patched:0,false_positive:0};
  vulns.forEach(v=>{ if(v.status && c[v.status]!==undefined) c[v.status]++; });
  return c;
}

function buildHeaderFooter(ipData) {
  const { ip, organization } = ipData;

  const header = new (d().Header)({
    children: [
      new (d().Table)({
        width: { size: R.CONTENT_W, type: "dxa" },
        columnWidths: [Math.floor(R.CONTENT_W * 0.6), Math.ceil(R.CONTENT_W * 0.4)],
        rows: [new (d().TableRow)({
          children: [
            tableCell([para([
              txt("THREAT-SCOPE  ", { font:"Arial", size:18, bold:true, color:cHex(R.C_RED) }),
              txt("Vulnerability Assessment Report", { font:"Arial", size:18, color:cHex(R.C_GRAY) })
            ])], { width:{size:Math.floor(R.CONTENT_W*0.6),type:"dxa"}, shading:{fill:cHex("FAFAFA"),type:"clear"} }),
            tableCell([para([
              txt(String(ip || "—"), { font:"Arial", size:18, bold:true, color:cHex(R.C_BG) }),
              txt(organization ? `  |  ${organization}` : "", { font:"Arial", size:16, color:cHex(R.C_GRAY) })
            ], { alignment:"right" })],
            { width:{size:Math.ceil(R.CONTENT_W*0.4),type:"dxa"}, shading:{fill:cHex("FAFAFA"),type:"clear"} }),
          ]
        })]
      }),
      hRule("DDDDDD")
    ]
  });

  const footer = new (d().Footer)({
    children: [
      hRule("DDDDDD"),
      para([
        txt("Generado por THREAT-SCOPE  |  Confidencial  |  ", { font:"Arial", size:16, color:cHex(R.C_GRAY) }),
        txt("Página ", { font:"Arial", size:16, color:cHex(R.C_GRAY) }),
        new (d().TextRun)({ children:[d().PageNumber ? d().PageNumber.CURRENT : "CURRENT"], font:"Arial", size:16, color:cHex(R.C_GRAY) }),
        txt(" de ", { font:"Arial", size:16, color:cHex(R.C_GRAY) }),
        new (d().TextRun)({ children:[d().PageNumber ? d().PageNumber.TOTAL_PAGES : "TOTAL_PAGES"], font:"Arial", size:16, color:cHex(R.C_GRAY) }),
      ], { alignment:"center" })
    ]
  });

  return { header, footer };
}

async function generateReport(ip) {
  if (!window.docx) {
    toast("La librería de reportes aún está cargando. Espera un momento.", "info");
    return;
  }

  const ipData = window.state?.ips?.[ip];
  if (!ipData) { toast("No se encontraron datos para esta IP.", "error"); return; }

  const panel = document.querySelector(`.panel--ip[data-ip="${ip}"]`);
  if (!panel) { toast("El panel de la IP no está visible.", "error"); return; }

  toast("Generando reporte, por favor espera…", "info", 6000);

  try {
    const chartImgs   = getIpChartImages(panel);
    const { header, footer } = buildHeaderFooter(ipData);

    const coverContent  = buildCoverPage(ipData);
    const chartsContent = buildChartsSection(chartImgs);
    const tableContent  = buildVulnTableSection(ipData.vulns || []);
    const detailContent = await buildVulnDetails(ipData.vulns || [], ipData);

    const doc = new (d().Document)({
      styles: {
        default: {
          document: { run: { font: "Arial", size: 20 } }
        },
        paragraphStyles: [
          { id:"Heading1", name:"Heading 1", basedOn:"Normal", next:"Normal", quickFormat:true,
            run:{ size:32, bold:true, font:"Arial", color:cHex(R.C_BG) },
            paragraph:{ spacing:{before:400,after:200}, outlineLevel:0 } },
          { id:"Heading2", name:"Heading 2", basedOn:"Normal", next:"Normal", quickFormat:true,
            run:{ size:26, bold:true, font:"Arial", color:cHex(R.C_BG) },
            paragraph:{ spacing:{before:280,after:140}, outlineLevel:1 } },
        ]
      },
      sections: [{
        properties: {
          page: {
            size: { width: R.PAGE_W, height: R.PAGE_H },
            margin: { top: R.MARGIN, right: R.MARGIN, bottom: R.MARGIN, left: R.MARGIN }
          }
        },
        headers: { default: header },
        footers: { default: footer },
        children: [
          ...coverContent,
          ...chartsContent,
          ...tableContent,
          ...detailContent,
        ]
      }]
    });

    const buffer = await (d().Packer).toBlob(doc);
    const safeIp = String(ip).replace(/[^a-zA-Z0-9.\-_]/g, "_");
    const date   = new Date().toISOString().slice(0,10);
    const fname  = `ThreatScope_${safeIp}_${date}.docx`;

    const url = URL.createObjectURL(buffer);
    const a   = document.createElement("a");
    a.href = url; a.download = fname; a.click();
    URL.revokeObjectURL(url);

    toast(`✅ Reporte generado: ${fname}`, "success", 5000);
  } catch(err) {
    console.error("Error generando reporte:", err);
    toast("Error al generar el reporte: " + err.message, "error", 6000);
  }
}

window.generateReport = generateReport;