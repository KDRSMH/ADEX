import { useState } from "react";
import RiskBadge from "./RiskBadge";
import RemediationPanel from "./RemediationPanel";

export default function FindingCard({ finding }) {
    const [isExpanded, setIsExpanded] = useState(false);

    return (
        <div
            style={{
                background: "#1e1e2e",
                border: "1px solid #2a2a3e",
                borderRadius: "0.75rem",
                padding: "1.25rem 1.5rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
                transition: "box-shadow 0.2s",
            }}
        >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "1rem" }}>
                <span style={{ color: "#e2e8f0", fontWeight: "600", fontSize: "0.95rem" }}>
                    {finding.title}
                </span>
                <RiskBadge color={finding.color} score={finding.risk_score} />
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <span style={{ color: "#64748b", fontSize: "0.78rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                    Affected
                </span>
                <span style={{ color: "#94a3b8", fontSize: "0.85rem", fontFamily: "monospace" }}>
                    {finding.affectedObj}
                </span>
            </div>

            <button
                onClick={() => setIsExpanded((prev) => !prev)}
                style={{
                    alignSelf: "flex-start",
                    background: "transparent",
                    border: "1px solid #334155",
                    color: "#94a3b8",
                    padding: "0.35rem 0.9rem",
                    borderRadius: "0.4rem",
                    fontSize: "0.8rem",
                    cursor: "pointer",
                    transition: "border-color 0.15s, color 0.15s",
                }}
                onMouseEnter={(e) => { e.target.style.borderColor = "#6366f1"; e.target.style.color = "#a5b4fc"; }}
                onMouseLeave={(e) => { e.target.style.borderColor = "#334155"; e.target.style.color = "#94a3b8"; }}
            >
                {isExpanded ? "Hide Remediation ▲" : "View Remediation ▼"}
            </button>

            {isExpanded && <RemediationPanel remediation={finding.remediation} />}
        </div>
    );
}
