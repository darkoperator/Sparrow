// The always-visible "this is not a real case" strip of the dev-only mock backend (plain DOM, outside React).
export const MOCK_BANNER_TEXT = "MOCK BACKEND — synthetic data";

export function mountMockBanner(): void {
  if (document.getElementById("mock-backend-banner")) return;
  const el = document.createElement("div");
  el.id = "mock-backend-banner";
  el.setAttribute("role", "status");
  el.textContent = MOCK_BANNER_TEXT;
  Object.assign(el.style, {
    position: "fixed",
    right: "8px",
    bottom: "8px",
    zIndex: "2147483647",
    padding: "2px 10px",
    font: "600 12px system-ui, sans-serif",
    background: "#b45309",
    color: "#fff",
    borderRadius: "4px",
    pointerEvents: "none",
  });
  document.body.appendChild(el);
}
