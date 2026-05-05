import { useState, useRef } from "react";
import { loadReport } from "./utils/loader";
import Dashboard from "./components/Dashboard";

function AdexLogo({ size = 1 }) {
  const rows = [
    { ad: "  ████   █████  ", ex: "████████ ██   ██" },
    { ad: " ██  ██ ██   ██ ", ex: "██       ██   ██" },
    { ad: " ██  ██ ██   ██ ", ex: "██        ██ ██ " },
    { ad: " ██████ ██   ██ ", ex: "██████     ███  " },
    { ad: " ██  ██ ██   ██ ", ex: "██        ██ ██ " },
    { ad: " ██  ██ ██   ██ ", ex: "██       ██   ██" },
    { ad: " ██  ██ █████   ", ex: "████████ ██   ██" },
  ];

  const ch = 9.6 * size;
  const lh = 16 * size;
  const totalW = 32 * ch;
  const totalH = rows.length * lh;

  function renderChars(text, x0, y, color) {
    return text.split("").map((c, i) => {
      if (c === " ") return null;
      return (
        <rect
          key={i}
          x={x0 + i * ch}
          y={y}
          width={ch - 1}
          height={lh - 2}
          fill={color}
          rx={1}
        />
      );
    });
  }

  return (
    <svg
      width={totalW}
      height={totalH}
      style={{ display: "block" }}
      aria-label="ADEX"
    >
      {rows.map((row, ri) => {
        const y = ri * lh;
        return (
          <g key={ri}>
            {renderChars(row.ad, 0, y, "#a00000")}
            {renderChars(row.ex, row.ad.length * ch, y, "#ffffff")}
          </g>
        );
      })}
    </svg>
  );
}


function ShieldRed({ size = 38 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-label="Pentest Shield">
      <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z"
        fill="#7f0000" stroke="#c00000" strokeWidth="1.2" />
      <path d="M9 12l2 2 4-4" stroke="#ff4444" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      <text x="12" y="19" textAnchor="middle" fill="#ff6666" fontSize="5" fontFamily="monospace" fontWeight="bold">PT</text>
    </svg>
  );
}

function ShieldBlue({ size = 38 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-label="SOC Shield">
      <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z"
        fill="#0a1a40" stroke="#1e50b0" strokeWidth="1.2" />
      <circle cx="12" cy="12" r="3.5" stroke="#4488ff" strokeWidth="1.5" fill="none" />
      <line x1="12" y1="5" x2="12" y2="8.5" stroke="#4488ff" strokeWidth="1.2" strokeLinecap="round" />
      <text x="12" y="19" textAnchor="middle" fill="#6699ff" fontSize="5" fontFamily="monospace" fontWeight="bold">SOC</text>
    </svg>
  );
}

export default function App() {
  const [report, setReport] = useState(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  async function handleFile(file) {
    if (!file) return;
    try {
      const data = await loadReport(file);
      setReport(data);
    } catch (_) { }
  }

  function onDragOver(e) { e.preventDefault(); setDragging(true); }
  function onDragLeave() { setDragging(false); }
  function onDrop(e) { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }


  if (report) {
    return (
      <div style={{ minHeight: "100vh", background: "#0f0f1a", padding: "2rem" }}>
        <header style={{
          display: "flex", justifyContent: "space-between",
          alignItems: "center", marginBottom: "2rem",
          borderBottom: "1px solid #1e1e2e", paddingBottom: "1.2rem",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
            <ShieldRed size={32} />
            <ShieldBlue size={32} />
            <div>
              <AdexLogo size={0.55} />
              <p style={{ color: "#475569", fontSize: "0.75rem", margin: "0.15rem 0 0" }}>
                {report.domain ?? "Active Directory Security Report"}
              </p>
            </div>
          </div>
          <button
            onClick={() => setReport(null)}
            style={{
              background: "transparent",
              border: "1px solid #334155",
              color: "#64748b",
              padding: "0.4rem 0.9rem",
              borderRadius: "0.4rem",
              fontSize: "0.8rem",
              cursor: "pointer",
              transition: "border-color 0.2s, color 0.2s",
            }}
            onMouseEnter={e => { e.target.style.borderColor = "#a00000"; e.target.style.color = "#e2e8f0"; }}
            onMouseLeave={e => { e.target.style.borderColor = "#334155"; e.target.style.color = "#64748b"; }}
          >
            Load New Report
          </button>
        </header>

        <Dashboard report={report} />
      </div>
    );
  }


  return (
    <div style={{
      minHeight: "100vh",
      background: "radial-gradient(ellipse at 50% 0%, #1a0000 0%, #0f0f1a 60%)",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      gap: "1.8rem",
      padding: "2rem",
    }}>
      {/* Kalkan ikonları */}
      <div style={{ display: "flex", gap: "1rem", alignItems: "center" }}>
        <ShieldRed size={48} />
        <ShieldBlue size={48} />
      </div>

      <AdexLogo size={0.85} />
      <p style={{
        color: "#a00000",
        margin: 0,
        fontSize: "0.85rem",
        letterSpacing: "0.18em",
        textTransform: "uppercase",
        fontFamily: "monospace",
      }}>
        Active Directory Security Auditor
      </p>
      <div style={{ width: "420px", height: "1px", background: "linear-gradient(90deg, transparent, #7f0000, transparent)" }} />
      <div
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        style={{
          width: "100%",
          maxWidth: "480px",
          border: `2px dashed ${dragging ? "#c00000" : "#2a1a1a"}`,
          borderRadius: "1rem",
          padding: "3rem 2rem",
          textAlign: "center",
          cursor: "pointer",
          background: dragging ? "#1e0a0a" : "rgba(160,0,0,0.04)",
          transition: "all 0.25s",
          boxShadow: dragging ? "0 0 24px rgba(192,0,0,0.15)" : "none",
        }}
      >
        <p style={{
          color: dragging ? "#ff4444" : "#5a3030",
          fontSize: "0.9rem",
          margin: 0,
          fontFamily: "monospace",
        }}>
          {dragging
            ? "↓  Release to load  ↓"
            : "Drop the report file here — or click to browse"}
        </p>
        <p style={{
          color: "#3a2020",
          fontSize: "0.75rem",
          marginTop: "0.5rem",
          fontFamily: "monospace",
        }}>
          report.json
        </p>
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".json"
        style={{ display: "none" }}
        onChange={(e) => handleFile(e.target.files[0])}
      />
    </div>
  );
}
