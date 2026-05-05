const FILTERS = [
    { label: "All", value: "all" },
    { label: "Critical", value: "red" },
    { label: "High", value: "orange" },
    { label: "Medium", value: "yellow" },
    { label: "Low", value: "green" },
];

const ACCENT = {
    all: "#6366f1",
    red: "#dc2626",
    orange: "#ea580c",
    yellow: "#ca8a04",
    green: "#16a34a",
};

export default function FilterBar({ activeFilter, onFilterChange }) {
    return (
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            {FILTERS.map(({ label, value }) => {
                const isActive = activeFilter === value;
                const accent = ACCENT[value];

                return (
                    <button
                        key={value}
                        onClick={() => onFilterChange(value)}
                        style={{
                            padding: "0.4rem 1rem",
                            borderRadius: "9999px",
                            fontSize: "0.8rem",
                            fontWeight: isActive ? "700" : "400",
                            cursor: "pointer",
                            transition: "all 0.15s",
                            background: isActive ? accent : "transparent",
                            color: isActive ? "#fff" : "#94a3b8",
                            border: isActive ? `1px solid ${accent}` : "1px solid #334155",
                        }}
                    >
                        {label}
                    </button>
                );
            })}
        </div>
    );
}
