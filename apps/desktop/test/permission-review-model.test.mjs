import assert from "node:assert/strict";
import { register } from "node:module";
import test from "node:test";

register(new URL("./helpers/ts-import-hooks.mjs", import.meta.url));
const { reviewThinkingLevels, selectedReviewThinkingLevel } = await import(
  "../src/features/settings/permission-review-model.ts"
);

const provider = {
  id: "provider",
  models: [
    { id: "reasoning", thinkingLevels: ["off", "low", "high"] },
    { id: "plain", thinkingLevels: ["off"] },
  ],
  supportsReasoning: true,
  supportedThinkingLevels: ["off", "minimal", "low", "medium", "high"],
};

test("review thinking starts empty without a fixed model", () => {
  assert.deepEqual(reviewThinkingLevels(provider, undefined, undefined), []);
  assert.equal(selectedReviewThinkingLevel(undefined, ["low", "high"]), undefined);
});

test("review thinking lists the selected model's configured levels only", () => {
  assert.deepEqual(reviewThinkingLevels(provider, "reasoning", undefined), ["low", "high"]);
  assert.deepEqual(reviewThinkingLevels(provider, "plain", undefined), []);
  assert.equal(selectedReviewThinkingLevel("low", ["low", "high"]), "low");
  assert.equal(selectedReviewThinkingLevel("low", []), undefined);
});

test("review thinking keeps distinct complete model IDs separate", () => {
  const routed = {
    ...provider,
    models: [
      { id: "vendor/reasoning", thinkingLevels: ["low"] },
      { id: "reasoning", thinkingLevels: ["high"] },
    ],
  };
  assert.deepEqual(reviewThinkingLevels(routed, "vendor/reasoning", undefined), ["low"]);
  assert.deepEqual(reviewThinkingLevels(routed, "reasoning", undefined), ["high"]);
});
