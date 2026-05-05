import { useState } from "react";
import FilterBar from "./FilterBar";
import FindingCard from "./FindingCard";

const SUMMARY_CARDS = [
    { label: "Total", color: "#6366f1", key: "all" },
    { label: "Critical", color: "#dc2626", key: "red" },
    { label: "High", color: "#ea580c", key: "orange" },
    { label: "Medium", color: "#ca8a04", key: "yellow" },
    { label: "Low", color: "#16a34a", key: "green" },
];

function countByColor(findings, color) {
    if (color === "all") return findings.length;
    return findings.filter((f) => f.color === color).length;
}

export default function Dashboard({ report }) {
    const [activeFilter, setActiveFilter] = useState("all");

    const findings = report?.findings ?? [];

    const filteredFindings =
        activeFilter === "all"
            ? findings
            : findings.filter((f) => f.color === activeFilter);

    return (
        <div style={{ display: "flex", flexDirection: "column", gap: "2rem" }}>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "1rem" }}>
                {SUMMARY_CARDS.map(({ label, color, key }) => (
                    <div
                        key={key}
                        style={{
                            background: "#1e1e2e",
                            border: `1px solid ${color}33`,
                            borderRadius: "0.75rem",
                            padding: "1rem 1.25rem",
                            display: "flex",
                            flexDirection: "column",
                            gap: "0.4rem",
                        }}
                    >
                        <span style={{ color: "#64748b", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                            {label}
                        </span>
                        <span style={{ color, fontSize: "2rem", fontWeight: "700", lineHeight: 1 }}>
                            {countByColor(findings, key)}
                        </span>
                    </div>
                ))}
            </div>

            <FilterBar activeFilter={activeFilter} onFilterChange={setActiveFilter} />

            {filteredFindings.length === 0 ? (
                <p style={{ color: "#475569", textAlign: "center", padding: "3rem 0" }}>
                    No findings match the selected filter.
                </p>
            ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                    {filteredFindings.map((finding, i) => (
                        <FindingCard key={finding.id ?? i} finding={finding} />
                    ))}
                </div>
            )}

        </div>
    );
}
