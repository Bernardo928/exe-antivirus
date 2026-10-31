import type { ComponentType } from "react";
import { Home } from "./Home";
import { Privacy, Terms } from "./Legal";
import { NotFound } from "./NotFound";

export const PAGES: Record<string, ComponentType> = {
  home: Home,
  privacidade: Privacy,
  termos: Terms,
  notfound: NotFound,
};
