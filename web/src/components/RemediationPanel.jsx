import { useState } from "react";

export default function RemediationPanel({ remediation }) {
    const [copied, setCopied] = useState(false);

    if (!remediation) {
        return (
            <p style={{ color: "#475569", fontSize: "0.85rem", margin: 0 }}>
                No remediation data available.
            </p>
        );
    }

    function copyToClipboard() {
        navigator.clipboard.writeText(remediation.powershell ?? "").then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        });
    }

    return (
        <div
            style={{
                borderTop: "1px solid #2a2a3e",
                paddingTop: "1rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.75rem",
            }}
        >
            {remediation.steps?.length > 0 && (
                <ol style={{ margin: 0, paddingLeft: "1.25rem", display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                    {remediation.steps.map((step, i) => (
                        <li key={i} style={{ color: "#94a3b8", fontSize: "0.85rem", lineHeight: 1.6 }}>
                            {step}
                        </li>
                    ))}
                </ol>
            )}

            {remediation.powershell && (
                <div style={{ position: "relative" }}>
                    <pre
                        style={{
                            background: "#0d0d1a",
                            border: "1px solid #1e293b",
                            borderRadius: "0.5rem",
                            padding: "0.75rem 1rem",
                            margin: 0,
                            fontSize: "0.78rem",
                            color: "#7dd3fc",
                            overflowX: "auto",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                        }}
                    >
                        {remediation.powershell}
                    </pre>
                    <button
                        onClick={copyToClipboard}
                        style={{
                            position: "absolute",
                            top: "0.5rem",
                            right: "0.5rem",
                            background: copied ? "#16a34a" : "#1e293b",
                            border: "none",
                            color: "#e2e8f0",
                            padding: "0.25rem 0.6rem",
                            borderRadius: "0.3rem",
                            fontSize: "0.7rem",
                            cursor: "pointer",
                            transition: "background 0.2s",
                        }}
                    >
                        {copied ? "Copied ✓" : "Copy"}
                    </button>
                </div>
            )}
        </div>
    );
}
