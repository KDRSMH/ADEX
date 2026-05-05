const RISK_MAP = {
    red: { label: "CRITICAL", bg: "#dc2626", text: "#fff" },
    orange: { label: "HIGH", bg: "#ea580c", text: "#fff" },
    yellow: { label: "MEDIUM", bg: "#ca8a04", text: "#fff" },
    green: { label: "LOW", bg: "#16a34a", text: "#fff" },
};

export default function RiskBadge({ color, score }) {
    const config = RISK_MAP[color] ?? { label: "INFO", bg: "#6b7280", text: "#fff" };

    return (
        <span
            style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.35rem",
                backgroundColor: config.bg,
                color: config.text,
                fontSize: "0.7rem",
                fontWeight: "700",
                letterSpacing: "0.05em",
                padding: "0.25rem 0.6rem",
                borderRadius: "9999px",
                whiteSpace: "nowrap",
            }}
        >
            {config.label}
            {score !== undefined && (
                <span style={{ opacity: 0.85, fontWeight: "400" }}>({score})</span>
            )}
        </span>
    );
}
