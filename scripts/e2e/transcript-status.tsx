import type { ComponentProps } from "react";
import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { en } from "@pi-desktop/i18n";
import type { AgentActivity, UiMessage } from "@pi-desktop/shared";
import { ChatTranscript } from "../../apps/desktop/src/features/chat/transcript/ChatTranscript";
import { useAppStore } from "../../apps/desktop/src/stores/app-store";

/** A turn stays visibly active even when its latest output stops changing. */
export async function transcriptStatusProbe() {
  const i18n = createInstance();
  await i18n.init({ lng: "en", resources: { en: { translation: en } } });
  const host = document.createElement("div");
  host.style.cssText =
    "position:absolute;inset:0;display:flex;flex-direction:column";
  document.body.append(host);
  const initial = useAppStore.getState();
  const root = createRoot(host);
  const failures: string[] = [];
  const checks: string[] = [];
  const check = (value: unknown, label: string) => {
    checks.push(label);
    if (!value) failures.push(label);
  };
  const sessionId = "status-lifecycle";
  const createdAt = new Date().toISOString();
  const user: UiMessage = {
    id: "user",
    role: "user",
    content: "Inspect the workspace",
    createdAt,
  };
  const answer: UiMessage = {
    id: "answer",
    role: "assistant",
    content: "I will inspect the files.",
    status: "streaming",
    createdAt,
  };
  const tool: UiMessage = {
    id: "tool",
    role: "tool",
    content: "",
    toolName: "Bash",
    toolCallId: "call",
    toolArgs: { command: "pwd" },
    toolStatus: "running",
    createdAt,
  };
  let props: ComponentProps<typeof ChatTranscript> = {
    sessionId,
    messages: [user],
    isRunning: true,
  };
  const render = async (update: Partial<typeof props> = {}) => {
    props = { ...props, ...update };
    flushSync(() =>
      root.render(
        <I18nextProvider i18n={i18n}>
          <ChatTranscript {...props} />
        </I18nextProvider>,
      ),
    );
    // Let React commit the deferred transcript projection before inspecting it.
    for (let task = 0; task < 2; task++) {
      await new Promise<void>((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = () => {
          channel.port1.close();
          channel.port2.close();
          resolve();
        };
        channel.port2.postMessage(null);
      });
    }
  };
  const activity = (value: AgentActivity | undefined) => {
    flushSync(() =>
      useAppStore.setState({
        agentStatuses: {
          [sessionId]: {
            sessionId,
            isRunning: true,
            pendingToolConfirmations: 0,
            activity: value,
          },
        },
      }),
    );
  };
  const indicator = (id: string) => host.querySelector(`[data-testid="${id}"]`);
  const oneStatus = (id: string, label: string) => {
    const lane = host.querySelector(".transcript-runtime-status");
    check(lane?.childElementCount === 1 && Boolean(indicator(id)), label);
    check(
      indicator(id)?.getAttribute("role") === "status",
      `${label}: accessible status`,
    );
  };
  const noStatus = (label: string) =>
    check(!host.querySelector(".transcript-runtime-status > *"), label);
  try {
    for (const mode of ["detailed", "compact"] as const) {
      flushSync(() =>
        useAppStore.setState({
          settings: {
            defaultMode: "agent",
            theme: "light",
            enterToSend: true,
            onboardingDismissed: true,
            thinkingDisplayMode: mode,
          },
          agentStatuses: {},
          pendingPlans: {},
        }),
      );
      await render({
        sessionId,
        messages: [user],
        isRunning: true,
        readingWindow: false,
      });
      oneStatus("working-indicator", `${mode}: send before first event`);
      await render({ messages: [user, answer] });
      oneStatus("working-indicator", `${mode}: partial answer remains active`);
      // No more deltas: an unchanged streaming message must not erase feedback.
      await render();
      oneStatus("working-indicator", `${mode}: quiet partial answer`);
      await render({ messages: [user, answer, tool] });
      oneStatus("working-indicator", `${mode}: running tool`);
      await render({
        messages: [
          user,
          answer,
          { ...tool, toolStatus: "success", content: "done" },
        ],
      });
      oneStatus(
        "working-indicator",
        `${mode}: completed tool before next status`,
      );
      activity({ phase: "waiting-model", since: Date.now() });
      oneStatus("run-activity-indicator", `${mode}: named model wait`);
      activity(undefined);
      oneStatus("working-indicator", `${mode}: cleared phase keeps fallback`);
      await render({
        messages: [
          user,
          { ...answer, content: "", thinking: "Inspecting files" },
        ],
      });
      oneStatus("working-indicator", `${mode}: thinking only`);
      await render({
        messages: [user, { ...answer, content: "Here is the result." }],
      });
      oneStatus("working-indicator", `${mode}: resumed answer`);
      for (const status of ["complete", "aborted", "error"] as const) {
        await render({
          messages: [user, { ...answer, status }],
          isRunning: false,
        });
        check(
          !host.querySelector(".transcript-runtime-status"),
          `${mode}: ${status} removes lane`,
        );
      }
    }
    await render({ messages: [user, answer], isRunning: true });
    for (const phase of [
      "starting",
      "waiting-model",
      "preparing",
      "recovering",
      "retrying",
    ] as const) {
      activity({ phase, since: Date.now() });
      oneStatus(
        "run-activity-indicator",
        `${phase}: partial text cannot hide runtime phase`,
      );
      check(
        indicator("run-activity-indicator")?.getAttribute("data-phase") ===
          phase,
        `${phase}: correct label owner`,
      );
    }
    activity(undefined);
    await render({ planningState: "planning" });
    oneStatus("planning-indicator", "planning remains visible after output");
    activity({ phase: "waiting-model", since: Date.now() });
    oneStatus(
      "run-activity-indicator",
      "runtime phase takes precedence over planning",
    );
    await render({ askPending: true });
    noStatus("question pending yields to user interaction");
    await render({
      askPending: false,
      pendingPermission: {
        sessionId,
        requestId: "permission",
        toolCallId: "call",
        toolName: "Bash",
        argsPreview: { command: "pwd" },
        risk: "low",
        reason: "fixture",
        receivedAt: Date.now(),
      },
    });
    noStatus("permission pending yields to approval");
    check(
      host.querySelector(".permission-card button"),
      "permission actions remain mounted",
    );
    await render({ pendingPermission: undefined });
    flushSync(() =>
      useAppStore.setState({
        pendingPlans: {
          [sessionId]: {
            id: "proposal",
            sessionId,
            turnId: "turn",
            toolCallId: "submit",
            kind: "plan",
            title: "Review plan",
            markdown: "Plan",
            plan: "Plan",
            question: "Proceed?",
            version: 1,
            status: "pending",
            createdAt,
            updatedAt: createdAt,
          },
        },
      }),
    );
    noStatus("plan approval yields to user interaction");
    flushSync(() => useAppStore.setState({ pendingPlans: {} }));
    oneStatus("run-activity-indicator", "approval resolved restores activity");
    await render({ readingWindow: true });
    check(
      !host.querySelector(".transcript-runtime-status"),
      "history reading has no live lane",
    );
    await render({ readingWindow: false });
    oneStatus("run-activity-indicator", "return to latest restores activity");
    await render({ sessionId: "other-session", planningState: undefined });
    oneStatus(
      "working-indicator",
      "session switch cannot inherit another session's phase",
    );
    await render({ sessionId });
    oneStatus(
      "run-activity-indicator",
      "return to running session restores its own phase",
    );
    await render({ isRunning: false });
    noStatus("terminal turn hides even a retained runtime phase");
    return { ok: failures.length === 0, checks, failures };
  } finally {
    flushSync(() => root.unmount());
    host.remove();
    useAppStore.setState({
      settings: initial.settings,
      agentStatuses: initial.agentStatuses,
      pendingPlans: initial.pendingPlans,
    });
  }
}
