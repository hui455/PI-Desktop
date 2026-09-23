import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { useState } from "react";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { catalogs } from "@pi-desktop/i18n";
import type { ModelBinding, ModelInfo } from "@pi-desktop/shared";
import { ModelSelectionPanes, useModelSelection } from "../../apps/desktop/src/components/settings/ModelSelectionPanes";
import { api } from "../../apps/desktop/src/lib/api";
import "../../apps/desktop/src/styles/tokens.css";
import "../../apps/desktop/src/styles/settings.css";
import "../../apps/desktop/src/styles/model-config.css";
import "../../apps/desktop/src/styles/providers.css";

const info = (id: string): ModelInfo => ({
  modelId: id,
  displayName: id,
  providerId: "fixture",
  capabilities: ["text"],
  source: "discovered",
  modalities: { input: ["text"], output: ["text"] },
  limit: { context: 128000, output: 8192 },
});
const discovered = "abcdefghijklmnop".split("").map((letter) => info(`fixture-${letter}`));
const discovery = { status: "ready" as const, models: discovered, canReload: false };
const painted = () => new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
const assert = (condition: unknown, message: string) => { if (!condition) throw Error(message); };

function Pane() {
  const [models, updateModels] = useState<ModelBinding[]>([]);
  const selection = useModelSelection(discovery, models, (update) => updateModels(update));
  currentModels = models;
  return <div className="provider-setup-dialog"><div className="provider-setup-body">
    <ModelSelectionPanes discovery={discovery} selection={selection}
      listTitle="Models from service" apiStyle="chat_completions" />
  </div></div>;
}

async function setup() {
  const i18n = createInstance();
  await i18n.init({ lng: "en", fallbackLng: "en", resources: {
    en: { translation: catalogs.en },
  } });
  api.lookupProviderModel = async () => ({ info: null });
  const mount = document.createElement("div");
  mount.id = "fixture";
  document.body.append(mount);
  const root = createRoot(mount);
  flushSync(() => root.render(<I18nextProvider i18n={i18n}><Pane /></I18nextProvider>));
  await painted();
}

const chosenRows = () => Array.from(document.querySelectorAll<HTMLElement>(".provider-chosen-row"));
const chosen = (id: string) => chosenRows().find((row) => row.querySelector(".provider-chosen-row-id")?.textContent === id);
const state = () => Object.fromEntries(chosenRows().map((row) => [
  row.querySelector(".provider-chosen-row-id")?.textContent,
  row.querySelector(".provider-chosen-advanced-toggle")?.getAttribute("aria-expanded"),
]));
const click = (id: string) => {
  const row = Array.from(document.querySelectorAll<HTMLElement>(".provider-models-row"))
    .find((row) => row.textContent?.includes(id));
  const checkbox = row?.querySelector<HTMLInputElement>("input[type=checkbox]");
  assert(checkbox, `missing checkbox for ${id}`);
  flushSync(() => checkbox.click());
};

declare global {
  var modelSelectionProbe: (phase: "select" | "finish") => Promise<unknown>;
}
let ready = false;
let currentModels: ModelBinding[] = [];
globalThis.modelSelectionProbe = async (phase) => {
  if (!ready) { await setup(); ready = true; }
  if (phase === "select") {
    click("fixture-a");
    click("fixture-b");
    await painted();
    assert(chosen("fixture-a") && chosen("fixture-b"), "both selected models must remain visible");
    const list = document.querySelector<HTMLElement>(".provider-chosen-list")!;
    return { afterSelection: state(), paneScrollTop: list.scrollTop, viewportHeight: list.clientHeight };
  }
  const toggle = chosen("fixture-b")?.querySelector<HTMLButtonElement>(".provider-chosen-advanced-toggle");
  assert(toggle, "the selected row's Advanced toggle must exist");
  flushSync(() => toggle.click());
  const manuallyClosed = state()["fixture-b"] === "false";
  flushSync(() => toggle.click());
  const manuallyReopened = state()["fixture-b"] === "true";
  click("fixture-e");
  await painted();
  const afterLastSelection = state();
  const list = document.querySelector<HTMLElement>(".provider-chosen-list")!;
  const listRect = list.getBoundingClientRect();
  const lastRect = chosen("fixture-e")!.querySelector(".provider-chosen-advanced-toggle")!.getBoundingClientRect();
  const lastHeadingVisible = lastRect.top >= listRect.top && lastRect.bottom <= listRect.bottom;
  const paneScrollTop = list.scrollTop;
  flushSync(() => document.querySelector<HTMLInputElement>(".provider-models-select-all")!.click());
  const afterBulk = state();
  click("fixture-p");
  click("fixture-p");
  await painted();
  const afterDeepSelection = state();
  const deepScrollTop = list.scrollTop;
  const deepScrollHeight = list.scrollHeight;
  const deepClientHeight = list.clientHeight;
  const deepWindowScroll = window.scrollY;
  const deepRect = chosen("fixture-p")!.querySelector(".provider-chosen-advanced-toggle")!.getBoundingClientRect();
  const deepHeadingVisible = deepRect.top >= listRect.top && deepRect.bottom <= listRect.bottom;
  const beforeCustom = state();
  const input = document.querySelector<HTMLInputElement>(".provider-custom-model-row input")!;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  assert(setter, "custom model input setter must exist");
  setter.call(input, "custom-fixture");
  input.dispatchEvent(new InputEvent("input", { bubbles: true, data: "custom-fixture", inputType: "insertText" }));
  flushSync(() => document.querySelector<HTMLButtonElement>(".provider-custom-model-row button")!.click());
  await painted();
  return { beforeCustom, afterCustom: state(), afterLastSelection, afterBulk, afterDeepSelection, paneScrollTop,
    lastHeadingVisible, deepScrollTop, deepScrollHeight, deepClientHeight, deepWindowScroll, deepHeadingVisible,
    modelIds: currentModels.map((model) => model.id), unchangedLimits: currentModels.every((model) => model.contextWindow === 128000 && model.maxTokens === 8192),
    manuallyClosed, manuallyReopened,
    allRowsRemain: !!chosen("fixture-a") && !!chosen("fixture-b") && !!chosen("custom-fixture") };
};
