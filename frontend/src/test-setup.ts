import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
// jsdom does not implement the native dialog top-layer methods.
HTMLDialogElement.prototype.showModal = function () { this.setAttribute("open", ""); };
HTMLDialogElement.prototype.close = function () { this.removeAttribute("open"); };
Object.defineProperty(window, "scrollTo", {value: () => {}, writable: true});
afterEach(() => {
  cleanup();
});
