// The pages' words, one JSON file per language in messages/, read with i18next through @openasy/ui (its ADR 0006).
// They follow the locale set on BrandProvider; English is the default, and messages from the API are shown as they come.
import { defineMessages } from "@openasy/ui";
import de from "./messages/de.json";
import en from "./messages/en.json";
import tr from "./messages/tr.json";

export const useT = defineMessages("waf", { en, tr, de });
export type T = ReturnType<typeof useT>;

let viewer = "en";
/** The language picked in the top bar, for dates and numbers written outside React (ADR 0006). App sets it while rendering. */
export const viewerLocale = (): string => viewer;
export function setViewerLocale(locale: string): void {
  viewer = locale;
}

/** A number with this many decimals, written as the viewer's language writes it: 4.9 in English, 4,9 in Turkish and German. */
export const fixed = (value: number, digits: number): string =>
  value.toLocaleString(viewer, { minimumFractionDigits: digits, maximumFractionDigits: digits, useGrouping: false });
