/* ══════════════════════════════════════════════════════
   THREAT-SCOPE — app.js  v2.0
   ══════════════════════════════════════════════════════ */
"use strict";

const state = {
  ips: {},
  activeTab: "summary",
  charts: {},
  orgFilter: "all"
};

window.state = state;

let saveTimer = null;

const api = {
  isOnline: false,

  async init() {
    try {
      const res = await fetch("/api/health");
      api.isOnline = res.ok;
    } catch { api.isOnline = false; }
    setSaveStatus(api.isOnline ? "saved" : "offline");
  },

  async load() {
    try {
      const res  = await fetch("/api/data");
      const data = await res.json();
      return data;
    } catch {
      return null;
    }
  },

  async save() {
    if (!api.isOnline) return;
    setSaveStatus("saving");
    try {
      await fetch("/api/data", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(state.ips)
      });
      setSaveStatus("saved");
    } catch {
      setSaveStatus("error");
    }
  },

  async uploadEvidence(file) {
    const fd = new FormData();
    fd.append("file", file);
    const res  = await fetch("/api/evidence", { method: "POST", body: fd });
    if (!res.ok) throw new Error("Upload failed");
    return await res.json();
  },

  async deleteEvidence(filename) {
    try {
      await fetch(`/api/evidence/${encodeURIComponent(filename)}`, { method: "DELETE" });
    } catch { }
  }
};

function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => api.save(), 1200);
}

function setSaveStatus(status) {
  const el = document.getElementById("saveIndicator");
  el.className = "save-indicator save-indicator--" + status;
  const titles = { saving:"Guardando…", saved:"Guardado", error:"Error al guardar", offline:"Sin servidor (solo local)" };
  el.title = titles[status] || "";
}

const SEVERITY_ORDER = ["critical","high","medium","low","info"];

function cvssToSeverity(score) {
  const n = parseFloat(score);
  if (isNaN(n)) return "info";
  if (n >= 9.0) return "critical";
  if (n >= 7.0) return "high";
  if (n >= 4.0) return "medium";
  if (n > 0)    return "low";
  return "info";
}

function textToSeverity(text) {
  if (!text) return "info";
  const t = text.toLowerCase();
  if (t.includes("critical")||t.includes("críti")) return "critical";
  if (t.includes("high")||t.includes("alta")||t.includes("alto")) return "high";
  if (t.includes("medium")||t.includes("media")||t.includes("moderate")||t.includes("warning")) return "medium";
  if (t.includes("low")||t.includes("baja")||t.includes("bajo")) return "low";
  return "info";
}

const SEV_COLORS = { critical:"#be1622", high:"#e85d04", medium:"#f4a261", low:"#95c11f", info:"#4a9eda" };
const SEV_BG     = { critical:"rgba(190,22,34,0.25)", high:"rgba(232,93,4,0.25)", medium:"rgba(244,162,97,0.2)", low:"rgba(149,193,31,0.2)", info:"rgba(74,158,218,0.2)" };
const SEV_LABELS = { critical:"CRÍTICA", high:"ALTA", medium:"MEDIA", low:"BAJA", info:"INFO" };
const STATUS_LABELS = { pending:"PENDIENTE", exploited:"EXPLOTADA", patched:"PARCHEADA", false_positive:"FALSO POSITIVO" };
const STATUS_COLORS = { pending:"rgba(136,136,133,0.3)", exploited:"rgba(190,22,34,0.3)", patched:"rgba(149,193,31,0.3)", false_positive:"rgba(199,125,255,0.3)" };
const STATUS_BORDERS= { pending:"#888885", exploited:"#be1622", patched:"#95c11f", false_positive:"#c77dff" };

function detectScanner(xmlDoc) {
  const root = xmlDoc.documentElement;
  const tag  = root.tagName.toLowerCase();
  if (tag === "nmaprun") return "nmap";
  if (tag.includes("zap") || root.querySelector("OWASPZAPReport,alertitem")) return "zap";
  if (root.querySelector("issues") || tag === "issues") return "burp";
  if (tag === "report" && root.querySelector("results,result")) return "openvas";
  if (root.querySelector("NessusClientData_v2,ReportHost")) return "nessus";
  return "generic";
}

function parseXML(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "application/xml");
  if (doc.querySelector("parsererror")) throw new Error("XML malformado");
  const type = detectScanner(doc);
  switch(type) {
    case "nmap":    return parseNmap(doc);
    case "zap":     return parseZAP(doc);
    case "burp":    return parseBurp(doc);
    case "openvas": return parseOpenVAS(doc);
    case "nessus":  return parseNessus(doc);
    default:        return parseGeneric(doc);
  }
}

function parseNmap(doc) {
  const results = [];
  doc.querySelectorAll("host").forEach(host => {
    const ip = host.querySelector("address[addrtype='ipv4'],address[addrtype='ipv6']")?.getAttribute("addr") || "unknown";
    host.querySelectorAll("port").forEach(portEl => {
      const portNum   = portEl.getAttribute("portid");
      const proto     = portEl.getAttribute("protocol") || "tcp";
      const state_    = portEl.querySelector("state")?.getAttribute("state") || "";
      const svcEl     = portEl.querySelector("service");
      const service   = [svcEl?.getAttribute("name")||"", svcEl?.getAttribute("product")||"", svcEl?.getAttribute("version")||""].filter(Boolean).join(" ");
      const scripts   = portEl.querySelectorAll("script");
      if (scripts.length) {
        scripts.forEach(s => {
          const out  = s.getAttribute("output") || "";
          const cves = out.match(/CVE-\d{4}-\d+/gi) || [];
          const cvssMatch = out.match(/(?:cvss|score)[:\s]+([0-9]+\.?[0-9]*)/i);
          const vecMatch  = out.match(/(?:vector)[:\s]+([A-Z0-9:\/.]+)/i);
          const cvssVal = cvssMatch ? cvssMatch[1] : null;
          const cvssVec = vecMatch ? vecMatch[1] : "";
          const cvssStr = cvssVal ? (cvssVec ? `${cvssVal} (${cvssVec})` : cvssVal) : "";
          if (out.length > 5) results.push(mkVuln({ ip, port:portNum, protocol:proto, portState:state_, service, name:s.getAttribute("id")||service||`Puerto ${portNum}`, description:out.substring(0,800), severity:cvssVal?cvssToSeverity(cvssVal):out.toLowerCase().includes("vuln")?"medium":"info", cvss:cvssStr, cve:cves.join(", "), scanner:"nmap" }));
        });
      } else if (state_ === "open") {
        results.push(mkVuln({ ip, port:portNum, protocol:proto, portState:state_, service, name:`Puerto abierto: ${portNum}/${proto} ${service}`.trim(), description:`Puerto ${portNum}/${proto} abierto. Servicio: ${service}`.trim(), severity:"info", cvss:"", cve:"", scanner:"nmap" }));
      }
    });
    doc.querySelectorAll("hostscript script").forEach(s => {
      const out  = s.getAttribute("output") || "";
      const cves = out.match(/CVE-\d{4}-\d+/gi) || [];
      const cvssMatch = out.match(/(?:cvss|score)[:\s]+([0-9]+\.?[0-9]*)/i);
      const vecMatch  = out.match(/(?:vector)[:\s]+([A-Z0-9:\/.]+)/i);
      const cvssVal = cvssMatch ? cvssMatch[1] : null;
      const cvssVec = vecMatch ? vecMatch[1] : "";
      const cvssStr = cvssVal ? (cvssVec ? `${cvssVal} (${cvssVec})` : cvssVal) : "";
      if (out.length > 5) results.push(mkVuln({ ip, port:"host", protocol:"", portState:"", service:"", name:s.getAttribute("id"), description:out.substring(0,800), severity:cvssVal?cvssToSeverity(cvssVal):"info", cvss:cvssStr, cve:cves.join(", "), scanner:"nmap" }));
    });
  });
  const firstIp = doc.querySelector("host address[addrtype='ipv4']")?.getAttribute("addr") || "unknown";
  const startTs = doc.documentElement.getAttribute("start");
  return { ip:firstIp, scanDate: startTs ? new Date(parseInt(startTs)*1000).toLocaleString("es") : "", vulns:results, scanner:"Nmap" };
}

function parseZAP(doc) {
  const results = [];
  let ip = "unknown";
  doc.querySelectorAll("site").forEach(site => {
    const host = site.getAttribute("host") || site.getAttribute("name") || "unknown";
    if (ip === "unknown") ip = host;
    site.querySelectorAll("alertitem").forEach(alert => {
      const risk = parseInt(alert.querySelector("riskcode")?.textContent || "0");
      const name = alert.querySelector("name")?.textContent || "ZAP Finding";
      const desc = stripHtml(alert.querySelector("desc")?.textContent || "");
      const sol  = stripHtml(alert.querySelector("solution")?.textContent || "");
      const ref  = stripHtml(alert.querySelector("reference")?.textContent || "");
      const cwe  = alert.querySelector("cweid")?.textContent || "";
      const uri  = alert.querySelector("uri,instances instance uri")?.textContent || "";
      const port = (uri.match(/:(\d+)\//) || [])[1] || "80";
      const riskdesc = alert.querySelector("riskdesc")?.textContent || "";
      let severity;
      if (riskdesc.toLowerCase().includes("critical")) severity = "critical";
      else if (risk === 3) severity = "high";
      else if (risk === 2) severity = "medium";
      else if (risk === 1) severity = "low";
      else severity = "info";
      results.push(mkVuln({ ip:host, port, protocol:"http", portState:"open", service:"web", name, description:desc.substring(0,800), severity, cvss:"", cve:cwe?`CWE-${cwe}`:"", scanner:"zap", solution:sol.substring(0,400), reference:ref.substring(0,200) }));
    });
  });
  return { ip, scanDate:new Date().toLocaleString("es"), vulns:results, scanner:"OWASP ZAP" };
}

function parseBurp(doc) {
  const results = [];
  let ip = "unknown";
  doc.querySelectorAll("issue,issues > item").forEach(issue => {
    const hostEl = issue.querySelector("host");
    const hostIp = hostEl?.getAttribute("ip") || extractIp(hostEl?.textContent || "");
    if (ip === "unknown" && hostIp) ip = hostIp;
    const name   = issue.querySelector("name,issuename,type")?.textContent || "BurpSuite Finding";
    const sevTxt = issue.querySelector("severity")?.textContent || "";
    const detail = stripHtml(issue.querySelector("issueDetail,detail,issuedetail")?.textContent || "");
    const remed  = stripHtml(issue.querySelector("remediationDetail,remediation")?.textContent || "");
    const path   = issue.querySelector("path,location,url")?.textContent || "";
    const port   = (hostEl?.textContent?.match(/:(\d+)$/) || [])[1] || "80";
    
    const cvssEl = issue.querySelector("cvss,cvssScore");
    const cvssVal = cvssEl ? parseFloat(cvssEl.textContent) : null;
    const cvssVecRaw = issue.querySelector("vulnerabilityClassifications,cvssVector")?.textContent || "";
    const vecMatch = cvssVecRaw.match(/CVSS:[A-Z0-9:\/.]+/i);
    const vecStr = vecMatch ? vecMatch[0] : "";
    const cvssStr = cvssVal ? (vecStr ? `${cvssVal} (${vecStr})` : `${cvssVal}`) : "";

    const cves   = (issue.querySelector("references,vuln_ref")?.textContent || "").match(/CVE-\d{4}-\d+/gi) || [];
    const severity = cvssVal ? cvssToSeverity(cvssVal) : textToSeverity(sevTxt);
    results.push(mkVuln({ ip:hostIp, port, protocol:"http", portState:"open", service:"web", name, description:detail.substring(0,800), severity, cvss:cvssStr, cve:cves.join(", "), scanner:"burp", solution:remed.substring(0,400), reference:path }));
  });
  return { ip, scanDate:new Date().toLocaleString("es"), vulns:results, scanner:"BurpSuite" };
}

function parseOpenVAS(doc) {
  const results = [];
  let ip = "unknown";
  doc.querySelectorAll("result").forEach(result => {
    const hostRaw = result.querySelector("host")?.textContent || "";
    const hostIp  = hostRaw.trim().split("\n")[0].trim();
    if (ip === "unknown" && hostIp) ip = hostIp;
    const portStr  = result.querySelector("port")?.textContent || "";
    const portNum  = (portStr.match(/(\d+)/) || [])[1] || "general";
    const proto    = portStr.toLowerCase().includes("udp") ? "udp" : "tcp";
    const name     = result.querySelector("name,nvt > name")?.textContent?.trim() || "OpenVAS Finding";
    const desc     = result.querySelector("description")?.textContent?.trim() || "";
    const sol      = result.querySelector("solution")?.textContent?.trim() || "";
    
    const cvssEl   = result.querySelector("severity,nvt > cvss_base,cvss_base");
    const cvssVal  = cvssEl ? parseFloat(cvssEl.textContent) : null;
    const cvssVecEl= result.querySelector("nvt > cvss_base_vector,cvss_base_vector");
    const cvssVec  = cvssVecEl ? cvssVecEl.textContent : "";
    const cvssStr  = cvssVal ? (cvssVec ? `${cvssVal} (${cvssVec})` : `${cvssVal}`) : "";

    const threat   = result.querySelector("threat,nvt > risk_factor");
    const severity = cvssVal ? cvssToSeverity(cvssVal) : textToSeverity(threat?.textContent || "");
    const cves     = Array.from(result.querySelectorAll("nvt > refs ref[type='cve'],cve")).map(e=>e.getAttribute("id")||e.textContent).filter(c=>c.startsWith("CVE-")).join(", ");
    const oid      = result.querySelector("nvt")?.getAttribute("oid") || "";
    results.push(mkVuln({ ip:hostIp, port:portNum, protocol:proto, portState:"open", service:result.querySelector("nvt > family")?.textContent||"", name, description:desc.substring(0,800), severity, cvss:cvssStr, cve:cves, scanner:"openvas", solution:sol.substring(0,400), reference:oid }));
  });
  return { ip, scanDate:doc.querySelector("creation_time,scan_start")?.textContent||new Date().toLocaleString("es"), vulns:results, scanner:"OpenVAS" };
}

function parseNessus(doc) {
  const results = [];
  let ip = "unknown";
  const sevMap = {0:"info",1:"low",2:"medium",3:"high",4:"critical"};
  doc.querySelectorAll("ReportHost").forEach(host => {
    const hostIp = host.querySelector("HostProperties tag[name='host-ip']")?.textContent || host.getAttribute("name") || "unknown";
    if (ip === "unknown") ip = hostIp;
    host.querySelectorAll("ReportItem").forEach(item => {
      const sevN = parseInt(item.getAttribute("severity")||"0");
      if (sevN === 0 && item.getAttribute("port")==="0") return;
      const port    = item.getAttribute("port")||"0";
      const proto   = item.getAttribute("protocol")||"tcp";
      const svc     = item.getAttribute("svc_name")||"";
      const name    = item.getAttribute("pluginName")||"Nessus Finding";
      const desc    = item.querySelector("description")?.textContent?.trim()||"";
      const sol     = item.querySelector("solution")?.textContent?.trim()||"";
      
      const cvss3   = item.querySelector("cvss3_base_score")?.textContent;
      const cvss2   = item.querySelector("cvss_base_score")?.textContent;
      const cvssVal = cvss3 || cvss2 || "";
      const vec3    = item.querySelector("cvss3_vector")?.textContent;
      const vec2    = item.querySelector("cvss_vector")?.textContent;
      const vecVal  = vec3 || vec2 || "";
      const cvssStr = cvssVal ? (vecVal ? `${cvssVal} (${vecVal})` : cvssVal) : "";

      const cve     = Array.from(item.querySelectorAll("cve")).map(e=>e.textContent).join(", ");
      results.push(mkVuln({ ip:hostIp, port, protocol:proto, portState:"open", service:svc, name, description:desc.substring(0,800), severity:sevMap[sevN]||"info", cvss:cvssStr, cve, scanner:"nessus", solution:sol.substring(0,400), reference:item.querySelector("see_also")?.textContent?.split("\n")[0]||"" }));
    });
  });
  return { ip, scanDate:new Date().toLocaleString("es"), vulns:results, scanner:"Nessus" };
}

function parseGeneric(doc) {
  const results = [];
  const rootTxt = doc.documentElement.textContent;
  const ip = (rootTxt.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)||["unknown"])[0];
  const tags = ["vulnerability","vuln","finding","issue","alert","risk","result"];
  let els = [];
  for (const t of tags) { els = Array.from(doc.querySelectorAll(t)); if (els.length) break; }
  if (!els.length) els = Array.from(doc.documentElement.children);
  els.forEach(el => {
    const name = el.querySelector("name,title")?.textContent||el.getAttribute("name")||el.tagName;
    const desc = el.querySelector("description,desc")?.textContent||el.textContent.substring(0,400);
    const sev  = el.querySelector("severity,risk,level")?.textContent||"";
    
    const cvssRaw = el.querySelector("cvss,cvss_base")?.textContent||"";
    const cvssVal = parseFloat(cvssRaw) || "";
    const vecRaw  = el.querySelector("cvss_vector,vector")?.textContent||"";
    const cvssStr = cvssVal ? (vecRaw ? `${cvssVal} (${vecRaw})` : `${cvssVal}`) : "";

    const cve  = (desc.match(/CVE-\d{4}-\d+/gi)||[]).join(", ");
    const port = el.querySelector("port")?.textContent||"unknown";
    results.push(mkVuln({ ip, port, protocol:"tcp", portState:"open", service:"", name:name.trim().substring(0,100), description:stripHtml(desc).substring(0,800), severity:cvssVal?cvssToSeverity(cvssVal):textToSeverity(sev), cvss:cvssStr, cve, scanner:"generic", solution:el.querySelector("solution,recommendation")?.textContent?.substring(0,400)||"" }));
  });
  return { ip, scanDate:new Date().toLocaleString("es"), vulns:results, scanner:"XML Genérico" };
}

function mkVuln(fields) {
  return { id:genId(), status:"pending", evidence:[], ...fields };
}

function genId() { return Math.random().toString(36).slice(2,10); }
function stripHtml(s) { return s ? s.replace(/<[^>]*>/g," ").replace(/\s+/g," ").trim() : ""; }
function extractIp(s) { return (s.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)||[s])[0]; }
function escHtml(s)   { return s ? String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;") : ""; }

function countBySeverity(vulns) {
  const c = {critical:0,high:0,medium:0,low:0,info:0};
  vulns.forEach(v => { if(c[v.severity]!==undefined) c[v.severity]++; });
  return c;
}
function countByStatus(vulns) {
  const c = {pending:0,exploited:0,patched:0,false_positive:0};
  vulns.forEach(v => { if(c[v.status]!==undefined) c[v.status]++; });
  return c;
}

function toast(msg, type="info", ms=3500) {
  const icons = {success:"✅",error:"❌",info:"ℹ️"};
  const el = document.createElement("div");
  el.className = `toast toast--${type}`;
  el.innerHTML = `<span>${icons[type]}</span>${escHtml(msg)}`;
  document.getElementById("toastContainer").appendChild(el);
  setTimeout(() => el.remove(), ms);
}

const btnPlus    = document.getElementById("btnPlus");
const dropdown   = document.getElementById("dropdown");
const actionsMenu= document.getElementById("actionsMenu");

function openMenu()  { dropdown.classList.add("is-open"); btnPlus.setAttribute("aria-expanded","true"); }
function closeMenu() { dropdown.classList.remove("is-open"); btnPlus.setAttribute("aria-expanded","false"); }
function toggleMenu(){ dropdown.classList.contains("is-open") ? closeMenu() : openMenu(); }

btnPlus.addEventListener("click", e => { e.stopPropagation(); toggleMenu(); });
document.addEventListener("click", e => { if(!actionsMenu.contains(e.target)) closeMenu(); });
document.addEventListener("keydown", e => { if(e.key==="Escape"){ closeMenu(); closeAddIpModal(); closeLightbox(); } });

document.getElementById("fileXml").addEventListener("change", async e => {
  const files = Array.from(e.target.files||[]);
  if(!files.length) return;
  closeMenu();
  let ok = 0;
  for (const f of files) {
    try {
      const data = parseXML(await f.text());
      if(!data.vulns.length) { toast(`${f.name}: sin vulnerabilidades detectadas.`,"info"); continue; }
      mergeIpData(data);
      ok++;
    } catch(err) { toast(`${f.name}: ${err.message}`,"error"); }
  }
  if(ok > 0) { toast(`${ok} archivo(s) XML cargado(s).`,"success"); renderAll(); scheduleSave(); }
  e.target.value = "";
});

document.getElementById("fileJson").addEventListener("change", async e => {
  const file = e.target.files?.[0];
  if(!file) return;
  closeMenu();
  try {
    importFromJson(JSON.parse(await file.text()));
    toast("JSON importado correctamente.","success");
    renderAll(); scheduleSave();
  } catch(err) { toast("Error JSON: "+err.message,"error"); }
  e.target.value = "";
});

document.getElementById("actionExportJson").addEventListener("click", () => { closeMenu(); exportJson(state.ips); });
document.getElementById("actionExportIpJson").addEventListener("click", () => {
  closeMenu();
  const ip = state.activeTab;
  if(!state.ips[ip]) { toast("Selecciona una pestaña de IP primero.","error"); return; }
  exportJson({[ip]:state.ips[ip]});
});

function exportJson(data) {
  const blob = new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = `threat-scope-${Date.now()}.json`; a.click();
  URL.revokeObjectURL(url);
  toast("Archivo exportado.","success");
}

function importFromJson(json) {
  const data = json.ips || json;
  Object.entries(data).forEach(([ip, ipData]) => {
    if(state.ips[ip]) {
      const existIds = new Set(state.ips[ip].vulns.map(v => v.id));
      const existKeys = new Set(state.ips[ip].vulns.map(v => `${v.name}|${v.port}|${v.protocol}`.toLowerCase()));
      
      (ipData.vulns||[]).forEach(nv => {
        const key = `${nv.name}|${nv.port}|${nv.protocol}`.toLowerCase();
        if(!existIds.has(nv.id) && !existKeys.has(key)) {
          state.ips[ip].vulns.push({evidence:[], ...nv});
          existIds.add(nv.id);
          existKeys.add(key);
        } else {
          const ev = state.ips[ip].vulns.find(v => v.id === nv.id || `${v.name}|${v.port}|${v.protocol}`.toLowerCase() === key);
          if(ev && nv.status && nv.status !== "pending") ev.status = nv.status;
        }
      });
      
      const newScanners = (ipData.scanner || "").split(",").map(s => s.trim());
      const currScanners = state.ips[ip].scanner.split(",").map(s => s.trim());
      newScanners.forEach(ns => {
        if(ns && !currScanners.includes(ns)) {
          state.ips[ip].scanner += ", " + ns;
          currScanners.push(ns);
        }
      });
    } else {
      const existKeys = new Set();
      const uniqueVulns = [];
      (ipData.vulns||[]).forEach(nv => {
        const key = `${nv.name}|${nv.port}|${nv.protocol}`.toLowerCase();
        if(!existKeys.has(key)) {
          uniqueVulns.push({evidence:[], ...nv});
          existKeys.add(key);
        }
      });
      state.ips[ip] = { ip, organization:ipData.organization||"", description:ipData.description||"", scanner:ipData.scanner||"JSON", scanDate:ipData.scanDate||"", vulns:uniqueVulns };
    }
  });
}

function mergeIpData({ip, scanDate, scanner, vulns}) {
  if(!ip || ip === "unknown") { 
    const key = scanner + "-" + Date.now(); 
    state.ips[key] = {ip:key, organization:"", description:"", scanner, scanDate, vulns}; 
    return; 
  }
  
  if(state.ips[ip]) {
    const existKeys = new Set(state.ips[ip].vulns.map(v => `${v.name}|${v.port}|${v.protocol}`.toLowerCase()));
    const newVulns = vulns.filter(v => {
      const key = `${v.name}|${v.port}|${v.protocol}`.toLowerCase();
      if(existKeys.has(key)) return false;
      existKeys.add(key);
      return true;
    });
    
    state.ips[ip].vulns.push(...newVulns);
    
    const currScanners = state.ips[ip].scanner.split(",").map(s => s.trim());
    if(!currScanners.includes(scanner)) {
      state.ips[ip].scanner += ", " + scanner;
    }
  } else {
    const existKeys = new Set();
    const uniqueVulns = vulns.filter(v => {
      const key = `${v.name}|${v.port}|${v.protocol}`.toLowerCase();
      if(existKeys.has(key)) return false;
      existKeys.add(key);
      return true;
    });
    
    state.ips[ip] = {ip, organization:"", description:"", scanner, scanDate, vulns:uniqueVulns};
  }
}

document.getElementById("btnIp").addEventListener("click", () => {
  const ips = Object.keys(state.ips);
  if(!ips.length) { toast("No hay IPs cargadas.","info"); return; }
  switchTab(ips[0]);
});

document.getElementById("actionAddIp").addEventListener("click", () => { closeMenu(); openAddIpModal(); });

function openAddIpModal()  { document.getElementById("modalAddIp").removeAttribute("hidden"); document.getElementById("inputIpAddress").focus(); }
function closeAddIpModal() { document.getElementById("modalAddIp").setAttribute("hidden",""); ["inputIpAddress","inputIpOrg","inputIpDesc"].forEach(id => document.getElementById(id).value=""); }

document.getElementById("modalAddIpClose").addEventListener("click", closeAddIpModal);
document.getElementById("modalAddIpCancel").addEventListener("click", closeAddIpModal);
document.getElementById("modalAddIp").addEventListener("click", e => { if(e.target===e.currentTarget) closeAddIpModal(); });

document.getElementById("modalAddIpConfirm").addEventListener("click", () => {
  const ip   = document.getElementById("inputIpAddress").value.trim();
  const org  = document.getElementById("inputIpOrg").value.trim();
  const desc = document.getElementById("inputIpDesc").value.trim();
  if(!ip) { toast("Introduce una dirección IP.","error"); return; }
  if(state.ips[ip]) { toast("Esta IP ya existe.","error"); return; }
  state.ips[ip] = { ip, organization:org, description:desc, scanner:"Manual", scanDate:new Date().toLocaleString("es"), vulns:[] };
  closeAddIpModal();
  renderAll(); scheduleSave();
  switchTab(ip);
  toast(`IP ${ip} añadida.`,"success");
});

function openLightbox(url, caption="") {
  document.getElementById("lightboxImg").src = url;
  document.getElementById("lightboxCaption").textContent = caption;
  document.getElementById("evidenceLightbox").removeAttribute("hidden");
}
function closeLightbox() { document.getElementById("evidenceLightbox").setAttribute("hidden",""); document.getElementById("lightboxImg").src=""; }
document.getElementById("lightboxClose").addEventListener("click", closeLightbox);
document.getElementById("evidenceLightbox").addEventListener("click", e => { if(e.target===e.currentTarget) closeLightbox(); });

function renderTabs() {
  const bar = document.getElementById("tabsBar");
  bar.querySelectorAll(".tab--ip").forEach(t=>t.remove());

  Object.values(state.ips).forEach(ipData => {
    const tab = document.createElement("button");
    tab.className = "tab tab--ip" + (state.activeTab===ipData.ip?" tab--active":"");
    tab.setAttribute("role","tab");
    tab.dataset.tab = ipData.ip;
    tab.innerHTML = `
      <span class="tab__icon">⬡</span>
      ${escHtml(ipData.ip)}
      ${ipData.organization ? `<span style="font-size:9px;color:var(--teal);margin-left:2px">${escHtml(ipData.organization.substring(0,12))}</span>` : ""}
      ${ipData.vulns.length > 0 ? `<span class="tab__count">${ipData.vulns.length}</span>` : ""}
      <button class="tab__close" title="Eliminar IP">✕</button>
    `;
    tab.addEventListener("click", e => { if(e.target.classList.contains("tab__close")) return; switchTab(ipData.ip); });
    tab.querySelector(".tab__close").addEventListener("click", e => { e.stopPropagation(); deleteIp(ipData.ip); });
    bar.appendChild(tab);
  });

  document.getElementById("tab-summary").classList.toggle("tab--active", state.activeTab==="summary");
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll(".panel").forEach(p=>p.classList.remove("panel--active"));
  const target = tabId==="summary"
    ? document.getElementById("panel-summary")
    : document.querySelector(`.panel--ip[data-ip="${tabId}"]`);
  if(target) target.classList.add("panel--active");
  renderTabs();
}

document.getElementById("tab-summary").addEventListener("click", () => switchTab("summary"));

function deleteIp(ip) {
  if(!confirm(`¿Eliminar la IP ${ip} y todos sus datos?`)) return;
  delete state.ips[ip];
  document.querySelector(`.panel--ip[data-ip="${ip}"]`)?.remove();
  Object.keys(state.charts).filter(k=>k.startsWith(ip)).forEach(k=>{ state.charts[k].destroy(); delete state.charts[k]; });
  if(state.activeTab===ip) state.activeTab="summary";
  renderAll(); scheduleSave();
  toast(`IP ${ip} eliminada.`,"success");
}

function renderAll() {
  document.getElementById("ipCount").textContent = `${Object.keys(state.ips).length} IPs`;
  renderTabs();
  renderSummaryPanel();
  renderIpPanels();
  switchTab(state.activeTab);
}

function renderSummaryPanel() {
  const filter = state.orgFilter;
  const allIps = Object.values(state.ips);
  const filteredIps = filter==="all" ? allIps : allIps.filter(d=>d.organization===filter);
  const allVulns = filteredIps.flatMap(d=>d.vulns);
  const sev = countBySeverity(allVulns);
  const st  = countByStatus(allVulns);

  document.getElementById("summaryStats").innerHTML = buildStatsHTML(allVulns.length, sev, st);
  document.getElementById("totalVulnsBadge").textContent = `${allVulns.length} total`;

  const orgs = [...new Set(allIps.map(d=>d.organization).filter(Boolean))];
  const filterEl = document.getElementById("summaryOrgFilter");
  const chipsEl  = document.getElementById("summaryOrgChips");
  if(orgs.length > 0) {
    filterEl.style.display = "block";
    chipsEl.innerHTML = `<button class="chip ${filter==="all"?"chip--active chip--org":""}" data-org="all">Todas</button>`;
    orgs.forEach(org => {
      const btn = document.createElement("button");
      btn.className = "chip chip--org" + (filter===org?" chip--active":"");
      btn.dataset.org = org;
      btn.textContent = org;
      btn.addEventListener("click", () => { state.orgFilter = org; renderSummaryPanel(); });
      chipsEl.appendChild(btn);
    });
    chipsEl.querySelector("[data-org='all']").addEventListener("click", () => { state.orgFilter="all"; renderSummaryPanel(); });
  } else { filterEl.style.display = "none"; }

  const orgChartEl = document.getElementById("summaryOrgChart");
  if(orgs.length > 1) {
    orgChartEl.style.display = "block";
    renderOrgChart(allIps);
  } else { orgChartEl.style.display = "none"; }

  destroyChart("chartByIp");
  renderChartByIp("chartByIp", filteredIps);
  renderDoughnutChart("chartGlobalDist", document.getElementById("chartGlobalDist"), sev);
  renderStatusPie("chartGlobalStatus", document.getElementById("chartGlobalStatus"), st);

  renderSummaryTable(filteredIps);
}

function renderSummaryTable(ips) {
  const tbody = document.getElementById("summaryTableBody");
  if(!ips.length) {
    tbody.innerHTML = `<tr class="table-empty"><td colspan="12">No hay datos. Carga un archivo XML o JSON.</td></tr>`;
    return;
  }
  tbody.innerHTML = ips.map(d => {
    const sev = countBySeverity(d.vulns);
    const st  = countByStatus(d.vulns);
    return `<tr>
      <td><a class="table-ip-link" data-ip="${escHtml(d.ip)}">${escHtml(d.ip)}</a>${d.description?`<br><span style="font-size:10px;color:var(--text-muted)">${escHtml(d.description)}</span>`:""}</td>
      <td class="table-org">${escHtml(d.organization)||"—"}</td>
      <td><span class="meta-tag meta-tag--scanner">${escHtml(d.scanner)}</span></td>
      <td class="${sev.critical?"num--critical":"num--0"}">${sev.critical||"—"}</td>
      <td class="${sev.high?"num--high":"num--0"}">${sev.high||"—"}</td>
      <td class="${sev.medium?"num--medium":"num--0"}">${sev.medium||"—"}</td>
      <td class="${sev.low?"num--low":"num--0"}">${sev.low||"—"}</td>
      <td class="${sev.info?"num--info":"num--0"}">${sev.info||"—"}</td>
      <td style="font-weight:600">${d.vulns.length}</td>
      <td class="${st.exploited?"num--critical":"num--0"}">${st.exploited||"—"}</td>
      <td class="${st.patched?"num--low":"num--0"}">${st.patched||"—"}</td>
      <td class="${st.false_positive?"num--info":"num--0"}">${st.false_positive||"—"}</td>
    </tr>`;
  }).join("");
  tbody.querySelectorAll(".table-ip-link").forEach(a => a.addEventListener("click", () => switchTab(a.dataset.ip)));
}

function buildStatsHTML(total, sev, st) {
  return `
    <div class="stat-card stat-card--total"><div class="stat-card__label">TOTAL VULNS</div><div class="stat-card__value">${total}</div></div>
    <div class="stat-card stat-card--critical"><div class="stat-card__label">CRÍTICAS</div><div class="stat-card__value">${sev.critical}</div></div>
    <div class="stat-card stat-card--high"><div class="stat-card__label">ALTAS</div><div class="stat-card__value">${sev.high}</div></div>
    <div class="stat-card stat-card--medium"><div class="stat-card__label">MEDIAS</div><div class="stat-card__value">${sev.medium}</div></div>
    <div class="stat-card stat-card--low"><div class="stat-card__label">BAJAS</div><div class="stat-card__value">${sev.low}</div></div>
    <div class="stat-card stat-card--info"><div class="stat-card__label">INFO</div><div class="stat-card__value">${sev.info}</div></div>
    <div class="stat-card stat-card--exploited"><div class="stat-card__label">EXPLOTADAS</div><div class="stat-card__value">${st.exploited}</div></div>
    <div class="stat-card stat-card--patched"><div class="stat-card__label">PARCHEADAS</div><div class="stat-card__value">${st.patched}</div></div>
    <div class="stat-card stat-card--fp"><div class="stat-card__label">FALSOS POSITIVOS</div><div class="stat-card__value">${st.false_positive}</div></div>
  `;
}

function renderIpPanels() {
  const template = document.getElementById("ipPanelTemplate");
  const main     = document.getElementById("mainContent");

  Object.values(state.ips).forEach(ipData => {
    let panel = main.querySelector(`.panel--ip[data-ip="${ipData.ip}"]`);
    if(!panel) {
      panel = template.content.cloneNode(true).querySelector(".panel--ip");
      panel.dataset.ip = ipData.ip;
      main.appendChild(panel);
      panel.querySelector(".ip-delete-btn").addEventListener("click", () => deleteIp(ipData.ip));
      panel.querySelector(".ip-report-btn").addEventListener("click", () => {
        if(state.activeTab !== ipData.ip) {
          switchTab(ipData.ip);
          setTimeout(() => window.generateReport(ipData.ip), 400);
        } else {
          window.generateReport(ipData.ip);
        }
      });
    }
    renderIpPanel(panel, ipData);
  });
}

function renderIpPanel(panel, ipData) {
  const { ip, organization, scanner, scanDate, vulns } = ipData;

  panel.querySelector(".ip-badge").textContent = ip;
  const orgBadge = panel.querySelector(".ip-org-badge");
  if(organization) { orgBadge.textContent = organization; orgBadge.style.display="inline-flex"; }
  else { orgBadge.style.display="none"; }
  panel.querySelector(".ip-scanner-badge").textContent = scanner;
  panel.querySelector(".ip-scan-date").textContent = scanDate ? `Escaneado: ${scanDate}` : "";

  const sev = countBySeverity(vulns);
  const st  = countByStatus(vulns);
  panel.querySelector(".ip-stats").innerHTML = buildStatsHTML(vulns.length, sev, st);

  renderChartByPort(ip, panel.querySelector(".chart-by-port"), vulns);
  renderDoughnutChart(ip+"-dist", panel.querySelector(".chart-dist"), sev);
  renderStatusPie(ip+"-status", panel.querySelector(".chart-status"), st);
  renderRemediationChart(ip+"-remed", panel.querySelector(".chart-remediation"), vulns);

  const scanners = [...new Set(vulns.map(v=>v.scanner))];
  const scannerChips = panel.querySelector(".scanner-chips");
  scannerChips.querySelectorAll(":not([data-value='all'])").forEach(e=>e.remove());
  scanners.forEach(s => {
    const c = document.createElement("button");
    c.className="chip"; c.dataset.filter="scanner"; c.dataset.value=s;
    c.textContent = s.toUpperCase();
    scannerChips.appendChild(c);
  });

  setupFilters(panel, ipData);
  renderVulnList(panel, ipData, {severity:"all",status:"all",scanner:"all",search:""});
}

function setupFilters(panel, ipData) {
  let filters = {severity:"all",status:"all",scanner:"all",search:""};
  const apply = () => renderVulnList(panel, ipData, filters);

  panel.querySelectorAll(".filter-bar .chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const ft = chip.dataset.filter;
      panel.querySelectorAll(`.chip[data-filter="${ft}"]`).forEach(c=>c.classList.remove("chip--active"));
      chip.classList.add("chip--active");
      filters[ft] = chip.dataset.value;
      apply();
    });
  });

  const searchEl = panel.querySelector(".filter-search");
  searchEl.addEventListener("input", () => { filters.search = searchEl.value.toLowerCase(); apply(); });
}

function renderVulnList(panel, ipData, {severity,status,scanner,search}) {
  const sevOrder = {critical:0,high:1,medium:2,low:3,info:4};
  let vulns = ipData.vulns.filter(v => {
    if(severity!=="all" && v.severity!==severity) return false;
    if(status!=="all" && v.status!==status) return false;
    if(scanner!=="all" && v.scanner!==scanner) return false;
    if(search && !`${v.name} ${v.cve} ${v.port} ${v.description}`.toLowerCase().includes(search)) return false;
    return true;
  }).sort((a,b)=>(sevOrder[a.severity]||4)-(sevOrder[b.severity]||4));

  const listEl = panel.querySelector(".vuln-list");
  if(!vulns.length) {
    listEl.innerHTML = `<div class="empty-state"><div class="empty-state__icon">🔍</div><div class="empty-state__title">SIN RESULTADOS</div><div class="empty-state__text">No hay vulnerabilidades con los filtros aplicados.</div></div>`;
    return;
  }

  listEl.innerHTML = vulns.map(v => buildVulnCardHTML(v)).join("");

  listEl.querySelectorAll(".vuln-card").forEach(card => {
    const vulnId = card.dataset.id;
    const vuln   = ipData.vulns.find(v=>v.id===vulnId);
    if(!vuln) return;

    card.querySelector(".vuln-card__header").addEventListener("click", () => card.classList.toggle("is-open"));

    card.querySelectorAll(".status-btn").forEach(btn => {
      btn.classList.toggle("is-active", btn.dataset.status===vuln.status);
      btn.addEventListener("click", e => {
        e.stopPropagation();
        vuln.status = btn.dataset.status;
        card.querySelectorAll(".status-btn").forEach(b=>b.classList.toggle("is-active",b.dataset.status===vuln.status));
        card.querySelector(".status-badge").className = `status-badge status-badge--${vuln.status}`;
        card.querySelector(".status-badge").textContent = STATUS_LABELS[vuln.status];
        refreshIpCharts(panel, ipData);
        renderSummaryPanel();
        scheduleSave();
      });
    });

    const evidenceInput = card.querySelector(".evidence-file-input");
    if(evidenceInput) {
      evidenceInput.addEventListener("change", async e => {
        const file = e.target.files?.[0];
        if(!file) return;
        const grid = card.querySelector(".evidence-grid");
        const loadingEl = document.createElement("div");
        loadingEl.className = "evidence-uploading";
        loadingEl.innerHTML = `<div class="evidence-spinner"></div> Subiendo…`;
        grid.appendChild(loadingEl);
        try {
          const result = await api.uploadEvidence(file);
          vuln.evidence = vuln.evidence || [];
          vuln.evidence.push(result.filename);
          loadingEl.remove();
          renderEvidenceGrid(card, vuln);
          scheduleSave();
          toast("Evidencia añadida.","success");
        } catch {
          loadingEl.remove();
          const reader = new FileReader();
          reader.onload = ev => {
            vuln.evidence = vuln.evidence || [];
            vuln.evidence.push("data:" + ev.target.result);
            renderEvidenceGrid(card, vuln);
            scheduleSave();
            toast("Evidencia guardada localmente.","info");
          };
          reader.readAsDataURL(file);
        }
        e.target.value = "";
      });
    }

    renderEvidenceGrid(card, vuln);
  });
}

function renderEvidenceGrid(card, vuln) {
  const grid = card.querySelector(".evidence-grid");
  grid.innerHTML = "";
  const evs = vuln.evidence || [];
  if(!evs.length) {
    const empty = document.createElement("span");
    empty.className = "evidence-empty";
    empty.textContent = "Sin evidencias adjuntadas.";
    grid.appendChild(empty);
    return;
  }
  evs.forEach((ev, idx) => {
    const url = ev.startsWith("data:") ? ev : `/evidence/${ev}`;
    const thumb = document.createElement("div");
    thumb.className = "evidence-thumb";
    thumb.innerHTML = `<img src="${url}" alt="Evidencia ${idx+1}" /><button class="evidence-thumb__del" title="Eliminar">✕</button>`;
    thumb.querySelector("img").addEventListener("click", () => openLightbox(url, `Evidencia ${idx+1} — ${vuln.name}`));
    thumb.querySelector(".evidence-thumb__del").addEventListener("click", async e => {
      e.stopPropagation();
      if(!ev.startsWith("data:")) await api.deleteEvidence(ev);
      vuln.evidence.splice(idx,1);
      renderEvidenceGrid(card, vuln);
      scheduleSave();
    });
    grid.appendChild(thumb);
  });
}

function buildVulnCardHTML(v) {
  const cveHtml = v.cve ? escHtml(v.cve).split(",").map(c=>c.trim()).filter(Boolean).join("<br>") : "";
  return `<div class="vuln-card" data-id="${v.id}" data-severity="${v.severity}" data-status="${v.status}">
    <div class="vuln-card__header">
      <span class="vuln-card__toggle">▶</span>
      <span class="vuln-card__sev vuln-card__sev--${v.severity}">${SEV_LABELS[v.severity]}</span>
      <span class="vuln-card__name" title="${escHtml(v.name)}">${escHtml(v.name)}</span>
      <div class="vuln-card__meta">
        ${v.port   ? `<span class="meta-tag meta-tag--port">${escHtml(String(v.port))}${v.protocol?"/"+v.protocol:""}</span>` : ""}
        ${v.cve    ? `<span class="meta-tag">${escHtml(v.cve.split(",")[0].trim())}</span>` : ""}
        <span class="meta-tag meta-tag--scanner">${escHtml(v.scanner.toUpperCase())}</span>
        <span class="status-badge status-badge--${v.status}">${STATUS_LABELS[v.status]}</span>
      </div>
    </div>
    <div class="vuln-card__body">
      ${v.description ? `<p class="vuln-body__desc">${escHtml(v.description)}</p>` : ""}
      <div class="vuln-body__row">
        ${v.port    ? `<div class="vuln-body__field"><div class="vuln-body__field-label">PUERTO</div><div class="vuln-body__field-value">${escHtml(String(v.port))}${v.protocol?"/"+v.protocol:""}</div></div>` : ""}
        ${v.service ? `<div class="vuln-body__field"><div class="vuln-body__field-label">SERVICIO</div><div class="vuln-body__field-value">${escHtml(v.service)}</div></div>` : ""}
        ${v.cvss    ? `<div class="vuln-body__field"><div class="vuln-body__field-label">CVSS SCORE</div><div class="vuln-body__field-value" style="color:${SEV_COLORS[v.severity]}">${escHtml(v.cvss)}</div></div>` : ""}
        ${cveHtml   ? `<div class="vuln-body__field"><div class="vuln-body__field-label">CVE / ID</div><div class="vuln-body__field-value" style="color:var(--blue)">${cveHtml}</div></div>` : ""}
        ${v.scanner ? `<div class="vuln-body__field"><div class="vuln-body__field-label">SCANNER</div><div class="vuln-body__field-value">${escHtml(v.scanner)}</div></div>` : ""}
      </div>
      ${v.solution  ? `<div class="vuln-body__row"><div class="vuln-body__field" style="flex:1"><div class="vuln-body__field-label">SOLUCIÓN / MITIGACIÓN</div><div class="vuln-body__field-value" style="white-space:pre-wrap;font-size:11px;color:var(--text-dim)">${escHtml(v.solution)}</div></div></div>` : ""}
      ${v.reference ? `<div class="vuln-body__row"><div class="vuln-body__field" style="flex:1"><div class="vuln-body__field-label">REFERENCIA</div><div class="vuln-body__field-value" style="font-size:11px;color:var(--blue)">${escHtml(v.reference.substring(0,200))}</div></div></div>` : ""}
      <div class="status-selector">
        <span class="status-selector__label">ESTADO:</span>
        <button class="status-btn" data-status="pending">Pendiente</button>
        <button class="status-btn" data-status="exploited">⚠ Explotada</button>
        <button class="status-btn" data-status="patched">✓ Parcheada</button>
        <button class="status-btn" data-status="false_positive">◇ Falso Positivo</button>
      </div>
      <div class="evidence-section">
        <div class="evidence-header">
          <span class="evidence-title">EVIDENCIA FOTOGRÁFICA</span>
          <label class="evidence-upload-label">
            📎 Agregar imagen
            <input type="file" accept="image/*" class="evidence-file-input" />
          </label>
        </div>
        <div class="evidence-grid"></div>
      </div>
    </div>
  </div>`;
}

function refreshIpCharts(panel, ipData) {
  const sev = countBySeverity(ipData.vulns);
  const st  = countByStatus(ipData.vulns);
  panel.querySelector(".ip-stats").innerHTML = buildStatsHTML(ipData.vulns.length, sev, st);
  renderStatusPie(ipData.ip+"-status", panel.querySelector(".chart-status"), st);
  renderRemediationChart(ipData.ip+"-remed", panel.querySelector(".chart-remediation"), ipData.vulns);
}

Chart.defaults.color = "#888885";
Chart.defaults.font.family = "'Share Tech Mono', monospace";

function destroyChart(id) { if(state.charts[id]){ state.charts[id].destroy(); delete state.charts[id]; } }

function renderChartByIp(chartId, ips) {
  destroyChart(chartId);
  const canvas = document.getElementById(chartId);
  if(!canvas || !ips.length) return;
  state.charts[chartId] = new Chart(canvas, {
    type: "bar",
    data: {
      labels: ips.map(d=>d.ip),
      datasets: SEVERITY_ORDER.map(sev=>({
        label: SEV_LABELS[sev],
        data: ips.map(d=>d.vulns.filter(v=>v.severity===sev).length),
        backgroundColor: SEV_BG[sev],
        borderColor: SEV_COLORS[sev],
        borderWidth:1, borderRadius:4
      }))
    },
    options: chartBarOpts(true)
  });
}

function renderChartByPort(chartId, canvas, vulns) {
  destroyChart(chartId);
  if(!canvas) return;
  const portMap = {};
  vulns.forEach(v => {
    const k = String(v.port||"N/A");
    if(!portMap[k]) portMap[k]={critical:0,high:0,medium:0,low:0,info:0,total:0};
    portMap[k][v.severity] = (portMap[k][v.severity]||0)+1;
    portMap[k].total++;
  });
  const sorted = Object.entries(portMap).sort((a,b)=>b[1].total-a[1].total).slice(0,20);
  state.charts[chartId] = new Chart(canvas, {
    type: "bar",
    data: {
      labels: sorted.map(([p])=>p),
      datasets: SEVERITY_ORDER.map(sev=>({
        label: SEV_LABELS[sev],
        data: sorted.map(([,c])=>c[sev]||0),
        backgroundColor: SEV_BG[sev],
        borderColor: SEV_COLORS[sev],
        borderWidth:1, borderRadius:3
      }))
    },
    options: chartBarOpts(true)
  });
}

function renderDoughnutChart(chartId, canvas, sevCounts) {
  destroyChart(chartId);
  if(!canvas) return;
  state.charts[chartId] = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: SEVERITY_ORDER.map(s=>SEV_LABELS[s]),
      datasets: [{ data: SEVERITY_ORDER.map(s=>sevCounts[s]||0), backgroundColor: SEVERITY_ORDER.map(s=>SEV_BG[s]), borderColor: SEVERITY_ORDER.map(s=>SEV_COLORS[s]), borderWidth:2 }]
    },
    options: doughnutOpts()
  });
}

function renderStatusPie(chartId, canvas, statusCounts) {
  destroyChart(chartId);
  if(!canvas) return;
  const keys  = ["pending","exploited","patched","false_positive"];
  const labs  = ["Pendiente","Explotada","Parcheada","Falso Positivo"];
  state.charts[chartId] = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: labs,
      datasets: [{
        data: keys.map(k=>statusCounts[k]||0),
        backgroundColor: keys.map(k=>STATUS_COLORS[k]),
        borderColor: keys.map(k=>STATUS_BORDERS[k]),
        borderWidth: 2
      }]
    },
    options: doughnutOpts()
  });
}

function renderRemediationChart(chartId, canvas, vulns) {
  destroyChart(chartId);
  if(!canvas) return;
  const sev = countBySeverity(vulns);
  const sevPatched = {};
  SEVERITY_ORDER.forEach(s => { sevPatched[s] = vulns.filter(v=>v.severity===s&&v.status==="patched").length; });
  state.charts[chartId] = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Remediadas","Pendientes / Otras"],
      datasets: [{
        data: [
          SEVERITY_ORDER.reduce((a,s)=>a+sevPatched[s],0),
          SEVERITY_ORDER.reduce((a,s)=>a+(sev[s]-sevPatched[s]),0)
        ],
        backgroundColor: ["rgba(149,193,31,0.3)","rgba(190,22,34,0.2)"],
        borderColor: ["#95c11f","#be1622"],
        borderWidth: 2
      }]
    },
    options: doughnutOpts()
  });
}

function renderOrgChart(allIps) {
  destroyChart("chartByOrg");
  const canvas = document.getElementById("chartByOrg");
  if(!canvas) return;
  const orgs = [...new Set(allIps.map(d=>d.organization).filter(Boolean))];
  if(!orgs.length) return;
  const datasets = SEVERITY_ORDER.map(sev=>({
    label: SEV_LABELS[sev],
    data: orgs.map(org => allIps.filter(d=>d.organization===org).flatMap(d=>d.vulns).filter(v=>v.severity===sev).length),
    backgroundColor: SEV_BG[sev], borderColor: SEV_COLORS[sev], borderWidth:1, borderRadius:4
  }));
  state.charts["chartByOrg"] = new Chart(canvas, {
    type:"bar", data:{labels:orgs,datasets}, options:chartBarOpts(true)
  });
}

function chartBarOpts(stacked) {
  return {
    responsive:true, maintainAspectRatio:false,
    plugins:{
      legend:{ labels:{font:{size:11},color:"#888885",padding:12} },
      tooltip:{backgroundColor:"#111",borderColor:"#333",borderWidth:1}
    },
    scales:{
      x:{stacked, grid:{color:"rgba(255,255,255,0.05)"}, ticks:{color:"#888885",font:{size:11}}},
      y:{stacked, beginAtZero:true, grid:{color:"rgba(255,255,255,0.05)"}, ticks:{color:"#888885",font:{size:11},precision:0}}
    }
  };
}

function doughnutOpts() {
  return {
    responsive:true, maintainAspectRatio:false, cutout:"62%",
    plugins:{
      legend:{ position:"bottom", labels:{font:{size:11},color:"#888885",padding:10,boxWidth:12} },
      tooltip:{backgroundColor:"#111",borderColor:"#333",borderWidth:1}
    }
  };
}

(async () => {
  await api.init();

  if(api.isOnline) {
    const saved = await api.load();
    if(saved && Object.keys(saved).length > 0) {
      Object.values(saved).forEach(ipData => {
        (ipData.vulns||[]).forEach(v => { if(!Array.isArray(v.evidence)) v.evidence=[]; });
        if(!ipData.organization) ipData.organization = "";
      });
      Object.assign(state.ips, saved);
      toast("Dashboard cargado desde el servidor.","success",2000);
    }
  } else {
    setSaveStatus("offline");
    toast("Servidor no disponible — los datos no se guardarán automáticamente.","info",5000);
  }

  document.getElementById("panel-summary").classList.add("panel--active");
  renderAll();
})();