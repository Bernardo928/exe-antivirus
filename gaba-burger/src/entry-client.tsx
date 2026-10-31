import { StrictMode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";
import "./styles.css";
import { PAGES } from "./pages";

const root = document.getElementById("root");
const Page = PAGES[document.body.dataset.page ?? "home"] ?? PAGES.notfound!;

if (root) {
  const app = (
    <StrictMode>
      <Page />
    </StrictMode>
  );
  // HTML pré-renderizado no build: hidrata. No modo dev (vazio): renderiza.
  if (root.hasChildNodes()) hydrateRoot(root, app);
  else createRoot(root).render(app);
}
