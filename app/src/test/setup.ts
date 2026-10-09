import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest globals are off, so Testing Library cannot register its own cleanup.
afterEach(() => {
  cleanup();
});

// jsdom has no layout; CodeMirror measures text with Range rects.
const noRects = () => ({ length: 0, item: () => null, [Symbol.iterator]: [][Symbol.iterator] }) as unknown as DOMRectList;
const zero = () => ({ x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, toJSON: () => ({}) }) as DOMRect;
Range.prototype.getClientRects = noRects;
Range.prototype.getBoundingClientRect = zero;
