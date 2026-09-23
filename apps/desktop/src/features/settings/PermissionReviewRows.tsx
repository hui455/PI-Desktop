import { useEffect, useRef, useState } from "react";
import {
  DEFAULT_PERMISSION_REVIEW_POLICY,
  MAX_PERMISSION_REVIEW_POLICY_CHARS,
  PERMISSION_REVIEW_POLICY_VERSION,
  THINKING_LEVELS,
  type AppSettings,
  type ProviderPublic,
} from "@pi-desktop/shared";
import { useTranslation } from "react-i18next";
import { Button } from "../../components/ui";
import { SettingsMenuSelect } from "../../components/settings/SettingsMenuSelect";
import { SettingsRow } from "./primitives";
import { syncPermissionPolicyDraft } from "./permission-policy-draft";

export function PermissionReviewRows({ settings, providers, saveSettings }: {
  settings: AppSettings;
  providers: ProviderPublic[];
  saveSettings: (patch: Partial<AppSettings>) => Promise<void>;
}) {
  const { t } = useTranslation();
  const binding = settings.autoReview;
  const savedPolicy = binding?.policyPrompt ?? DEFAULT_PERMISSION_REVIEW_POLICY;
  const [policyDraft, setPolicyDraft] = useState(savedPolicy);
  const previousSavedPolicy = useRef(savedPolicy);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [savingBinding, setSavingBinding] = useState(false);
  const writeInFlight = useRef(false);
  const [policySaveFailed, setPolicySaveFailed] = useState(false);
  const [bindingSaveFailed, setBindingSaveFailed] = useState(false);
  const busy = savingPolicy || savingBinding;
  const policyDirty = policyDraft !== savedPolicy;
  const policyLength = [...policyDraft].length;
  const policyInvalid = !policyDraft.trim() || policyLength > MAX_PERMISSION_REVIEW_POLICY_CHARS;
  // Provider refreshes and remote settings updates must not erase unsaved edits.
  useEffect(() => {
    const previous = previousSavedPolicy.current;
    setPolicyDraft((current) => syncPermissionPolicyDraft(current, previous, savedPolicy));
    previousSavedPolicy.current = savedPolicy;
  }, [savedPolicy]);

  const persistPolicy = async (policyPrompt: string | undefined) => {
    if (writeInFlight.current) return;
    writeInFlight.current = true;
    setSavingPolicy(true);
    setPolicySaveFailed(false);
    try {
      await saveSettings({ autoReview: { ...binding, policyPrompt } });
      setPolicyDraft(policyPrompt ?? DEFAULT_PERMISSION_REVIEW_POLICY);
    } catch {
      setPolicySaveFailed(true);
    } finally {
      writeInFlight.current = false;
      setSavingPolicy(false);
    }
  };
  const persistReviewSetting = async (patch: Partial<AppSettings>) => {
    if (writeInFlight.current) return;
    writeInFlight.current = true;
    setSavingBinding(true);
    setBindingSaveFailed(false);
    try {
      await saveSettings(patch);
    } catch {
      setBindingSaveFailed(true);
    } finally {
      writeInFlight.current = false;
      setSavingBinding(false);
    }
  };
  const models = providers.filter((provider) => provider.enabled && (
    provider.hasSecret || provider.hasOauth || provider.authKind === "none"
  ))
    .flatMap((provider) => provider.models.map((model) => ({
      id: JSON.stringify([provider.id, model.id]), label: `${provider.name} / ${model.id}`,
    })));
  const selected = binding?.providerId && binding.modelId
    ? JSON.stringify([binding.providerId, binding.modelId]) : "follow";

  return (
    <>
      <SettingsRow title={t("settings.approvalReviewer")} description={t("settings.approvalReviewerDesc")}>
        <SettingsMenuSelect
          label={t("settings.approvalReviewer")}
          value={settings.approvalReviewer ?? "user"}
          busy={busy}
          options={[
            { id: "user", label: t("settings.reviewByUser") },
            { id: "auto_review", label: t("settings.reviewByModel") },
          ]}
          onChange={(value) => void persistReviewSetting({ approvalReviewer: value === "auto_review" ? "auto_review" : "user" })}
        />
      </SettingsRow>
      <>
          <SettingsRow title={t("settings.reviewModel")} description={t("settings.reviewModelDesc")}>
            <SettingsMenuSelect
              label={t("settings.reviewModel")}
              value={selected}
              busy={busy}
              options={[{ id: "follow", label: t("settings.reviewFollowSession") }, ...models,
                ...(selected !== "follow" && !models.some((model) => model.id === selected)
                  ? [{ id: selected, label: t("settings.reviewModelUnavailable"), disabled: true }]
                  : []),
              ]}
              onChange={(value) => {
                const model = models.find((candidate) => candidate.id === value);
                if (value !== "follow" && !model) return;
                const [providerId, modelId] = value === "follow" ? [] : JSON.parse(model!.id) as string[];
                void persistReviewSetting({ autoReview: {
                  ...binding,
                  providerId,
                  modelId,
                  thinkingLevel: binding?.thinkingLevel ?? "off",
                } });
              }}
            />
          </SettingsRow>
          <SettingsRow title={t("settings.reviewThinking")} description={t("settings.reviewThinkingDesc")}>
            <SettingsMenuSelect
              label={t("settings.reviewThinking")}
              value={binding?.thinkingLevel ?? "off"}
              busy={busy}
              options={THINKING_LEVELS.map((level) => ({ id: level, label: level }))}
              onChange={(value) => {
                const thinkingLevel = THINKING_LEVELS.find((level) => level === value);
                if (thinkingLevel) void persistReviewSetting({ autoReview: { ...binding, thinkingLevel } });
              }}
            />
          </SettingsRow>
          <p className="settings-description">{t("settings.reviewCostCaution")}</p>
          {bindingSaveFailed ? <p role="alert">{t("settings.reviewSettingsSaveFailed")}</p> : null}
          <details className="settings-row permission-review-policy" style={{ display: "block" }}>
            <summary>{t("settings.reviewPolicyTitle")} · {t("settings.reviewPolicyVersion", { version: PERMISSION_REVIEW_POLICY_VERSION })} · {t(binding?.policyPrompt === undefined ? "settings.reviewPolicyDefault" : "settings.reviewPolicyCustom")}</summary>
            <p className="settings-description">{t("settings.reviewPolicyDesc")}</p>
            <label htmlFor="permission-review-policy-draft">{t("settings.reviewPolicyEditor")}</label>
            <textarea
              id="permission-review-policy-draft"
              className="field-textarea"
              rows={15}
              value={policyDraft}
              disabled={busy}
              onChange={(event) => { setPolicyDraft(event.target.value); setPolicySaveFailed(false); }}
              aria-invalid={policyInvalid}
              aria-describedby="permission-review-policy-help"
            />
            <p id="permission-review-policy-help" className="settings-description">
              {t("settings.reviewPolicyLength", { count: policyLength, max: MAX_PERMISSION_REVIEW_POLICY_CHARS })}
              {policyInvalid ? ` · ${t("settings.reviewPolicyInvalid")}` : ""}
            </p>
            <div className="permission-review-policy-actions" style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: "var(--space-3)" }}>
              <Button type="button" disabled={busy || !policyDirty || policyInvalid}
                onClick={() => void persistPolicy(policyDraft === DEFAULT_PERMISSION_REVIEW_POLICY ? undefined : policyDraft)}>
                {t("settings.reviewPolicySave")}
              </Button>
              <Button variant="secondary" type="button" disabled={busy || (binding?.policyPrompt === undefined && !policyDirty)}
                onClick={() => void persistPolicy(undefined)}>
                {t("settings.reviewPolicyRestore")}
              </Button>
              {policyDirty ? <span role="status">{t("settings.reviewPolicyUnsaved")}</span> : null}
            </div>
            {policySaveFailed ? <p role="alert">{t("settings.reviewPolicySaveFailed")}</p> : null}
            <p className="settings-description">{t("settings.reviewPolicyBoundary")}</p>
          </details>
      </>
    </>
  );
}
