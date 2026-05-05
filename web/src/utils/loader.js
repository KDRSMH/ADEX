export async function loadReport(file) {
    return new Promise((resolve, reject) => {
        if (!file) {
            const err = new Error("No file selected.");
            _showError(err.message);
            return reject(err);
        }

        if (!file.name.endsWith(".json")) {
            const err = new Error(`"${file.name}" is not a valid JSON file.`);
            _showError(err.message);
            return reject(err);
        }

        const reader = new FileReader();

        reader.onload = (event) => {
            try {
                const data = JSON.parse(event.target.result);
                resolve(data);
            } catch (parseError) {
                const msg = `JSON parse error: ${parseError.message}`;
                _showError(msg);
                reject(new Error(msg));
            }
        };

        reader.onerror = () => {
            const msg = `File could not be read: ${reader.error?.message ?? "Unknown error"}`;
            _showError(msg);
            reject(new Error(msg));
        };

        reader.readAsText(file, "utf-8");
    });
}

function _showError(message) {
    console.error("[Corvus Loader]", message);

    let banner = document.getElementById("corvus-error-banner");
    if (!banner) {
        banner = document.createElement("div");
        banner.id = "corvus-error-banner";
        banner.style.cssText = `
      position: fixed;
      top: 1rem;
      right: 1rem;
      background: #dc2626;
      color: #fff;
      padding: 0.75rem 1.25rem;
      border-radius: 0.5rem;
      font-family: monospace;
      font-size: 0.9rem;
      z-index: 9999;
      max-width: 400px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;
        document.body.appendChild(banner);
    }

    banner.textContent = `⚠ ${message}`;
    banner.style.display = "block";

    setTimeout(() => {
        if (banner) banner.style.display = "none";
    }, 5000);
}
