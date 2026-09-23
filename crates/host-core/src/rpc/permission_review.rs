use super::*;
use rusqlite::{params as sql_params, OptionalExtension};

/// Match the tool executor's canonical denylist before any action is sent to
/// the external reviewer. A move's destination is an independent target.
pub(super) fn sensitive_native_target(
    tool_name: &str,
    args: &Value,
    root: Option<&str>,
    scratch: Option<&std::path::Path>,
) -> bool {
    if !matches!(tool_name, "Read" | "Write" | "Edit") {
        return false;
    }
    let Some(root) = root else {
        return false;
    };
    let Some(requested) = args.get("path").and_then(Value::as_str) else {
        return false;
    };
    let is_sensitive = |path: &str| {
        workspace::resolve_tool_path_with_external(std::path::Path::new(root), scratch, path, true)
            .is_ok_and(|(resolved, _)| tools::ignore_rules::is_sensitive_path(&resolved))
    };
    if is_sensitive(requested) {
        return true;
    }
    if tool_name != "Edit" {
        return false;
    }
    args.get("ops")
        .and_then(Value::as_str)
        .and_then(|ops| tools::hashline::parse_ops(ops).ok())
        .is_some_and(|parsed| {
            parsed.ops.into_iter().any(|op| match op {
                tools::hashline::ParsedOp::Mv { dest } => is_sensitive(&dest),
                _ => false,
            })
        })
}

pub(super) fn running_turn(state: &AppState, session_id: &str, turn_id: &str) -> bool {
    match state.db.conn().query_row(
        "SELECT EXISTS(SELECT 1 FROM turns WHERE id = ?1 AND session_id = ?2 AND status = 'running')",
        sql_params![turn_id, session_id], |row| row.get::<_, bool>(0),
    ) {
        Ok(running) => running,
        Err(error) => { tracing::warn!(%error, "permission turn check failed"); false }
    }
}

pub(super) fn originating_user_message_id(
    state: &AppState,
    session_id: &str,
    turn_id: Option<&str>,
) -> Option<String> {
    let turn_id = turn_id?;
    if !running_turn(state, session_id, turn_id) {
        return None;
    }
    match state
        .db
        .conn()
        .query_row(
            "SELECT m.id FROM messages m JOIN turns t ON t.id = ?2
         WHERE m.session_id = ?1 AND m.role = 'user' AND t.session_id = ?1
           AND (m.turn_id = t.id OR (
             m.turn_id IS NULL AND m.created_at <= t.started_at
             AND m.created_at > COALESCE((SELECT MAX(p.started_at) FROM turns p
               WHERE p.session_id = t.session_id AND p.started_at < t.started_at), 0)
           )) ORDER BY m.seq DESC LIMIT 1",
            sql_params![session_id, turn_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
    {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(%error, "permission user-message lookup failed");
            None
        }
    }
}

fn unsafe_context(text: &str) -> bool {
    let lower = text.to_ascii_lowercase().replace('_', "");
    [
        "password",
        "secret",
        "privatekey",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "bearer ",
        "-----begin",
        "sk-",
        "ghp",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn review_evidence_safe(text: &str, max_chars: usize) -> bool {
    text.chars().count() <= max_chars
        && !text.contains("… (+")
        && !text.contains("…[truncated]")
        && !unsafe_context(text)
        && audit::redact_credentials(text) == text
}

fn context_complete(user_request: &str, argument_text: &str, turn_running: bool) -> bool {
    turn_running
        && !user_request.is_empty()
        && review_evidence_safe(user_request, 4_000)
        && review_evidence_safe(argument_text, 8_000)
}

/// The approved artifact, not a model's account of it, is authoritative for
/// a currently running Plan/Goal execution. An invalid artifact fails closed.
fn approved_execution_context(
    st: &AppState,
    session_id: &str,
    turn_id: Option<&str>,
) -> Result<Option<(String, String)>, ()> {
    let Some(turn_id) = turn_id else {
        return Ok(None);
    };
    let mut statement = st
        .db
        .conn()
        .prepare_cached(
            "SELECT request_id FROM plan_approvals WHERE session_id = ?1
         AND status = 'approved' AND execution_state = 'running'",
        )
        .map_err(|_| ())?;
    let mut rows = statement.query(sql_params![session_id]).map_err(|_| ())?;
    let Some(row) = rows.next().map_err(|_| ())? else {
        return Ok(None);
    };
    let proposal_id: String = row.get(0).map_err(|_| ())?;
    if rows.next().map_err(|_| ())?.is_some() {
        return Err(());
    }
    drop(rows);
    drop(statement);
    let proposal = plans::get_proposal(&st.db, &proposal_id)
        .map_err(|_| ())?
        .ok_or(())?;
    let artifact = proposal.artifact.as_ref().ok_or(())?;
    let kind = plans::normalize_kind(&proposal.kind).ok_or(())?;
    let root = resolve_tool_workspace(st, session_id)
        .map_err(|_| ())?
        .ok_or(())?;
    let root = Path::new(&root);
    plans::verify_artifact(root, kind, artifact).map_err(|_| ())?;
    let artifact_path =
        plans::safe_artifact_path(root, kind, &artifact.relative_path).map_err(|_| ())?;
    let approved_plan = std::fs::read_to_string(artifact_path).map_err(|_| ())?;
    if approved_plan != proposal.markdown
        || approved_plan.is_empty()
        || !review_evidence_safe(&approved_plan, 4_000)
    {
        return Err(());
    }
    // An active plan does not authorize an unrelated subsequent user request:
    // the originating user text must belong to the approved proposal's turn.
    let origin_id: String = st
        .db
        .conn()
        .query_row(
            "SELECT m.id FROM messages m JOIN turns t ON t.id = ?2
         WHERE m.session_id = ?1 AND m.role = 'user' AND t.session_id = ?1
           AND (m.turn_id = t.id OR (m.turn_id IS NULL AND m.created_at <= t.started_at
             AND m.created_at > COALESCE((SELECT MAX(p.started_at) FROM turns p
                 WHERE p.session_id = t.session_id AND p.started_at < t.started_at), 0)))
         ORDER BY m.seq DESC LIMIT 1",
            sql_params![session_id, proposal.turn_id],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    let session = sessions::get_session_with_options(
        &st.db,
        session_id,
        sessions::SessionReadOptions {
            message_around: Some(origin_id.clone()),
            message_limit: Some(1),
            ..Default::default()
        },
    )
    .map_err(|_| ())?
    .ok_or(())?;
    let user_request = session
        .messages
        .first()
        .filter(|message| message.id == origin_id && message.role == "user")
        .map(|message| message.content.clone())
        .ok_or(())?;
    if !running_turn(st, session_id, turn_id) {
        return Err(());
    }
    Ok(Some((user_request, approved_plan)))
}

pub(super) async fn claim(
    state: &Arc<Mutex<AppState>>,
    params: &Value,
    tx: &mpsc::UnboundedSender<String>,
) -> Result<Value, JsonRpcError> {
    let request_id = params
        .get("requestId")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(1002, "requestId required", "INVALID_PARAMS"))?;
    let mut st = state.lock().await;
    let configured_policy = st
        .db
        .get_setting("app")
        .map_err(|error| rpc_err(1000, error.to_string(), "INTERNAL"))?
        .and_then(|settings| {
            settings
                .get("autoReview")
                .and_then(|binding| binding.get("policyPrompt"))
                .cloned()
        });
    if configured_policy
        .as_ref()
        .is_some_and(|policy| !valid_review_policy(policy))
    {
        st.permissions
            .takeover_review(request_id)
            .map_err(|error| rpc_err(1008, error.clone(), &error))?;
        emit_notification(
            tx,
            "permissions.reviewUpdated",
            json!({
                "requestId": request_id, "reviewState": "user",
                "reason": "Review policy is invalid; human approval is required",
            }),
        )
        .await;
        return Err(rpc_err(
            1008,
            "review policy is invalid",
            "REVIEW_NOT_AVAILABLE",
        ));
    }
    let (token, request, fingerprint, turn_id, user_message_id, workspace_path) = st
        .permissions
        .claim_review(request_id)
        .map_err(|error| rpc_err(1008, error.clone(), &error))?;
    let session =
        user_message_id.as_deref().and_then(|id| {
            match sessions::get_session_with_options(
                &st.db,
                &request.session_id,
                sessions::SessionReadOptions {
                    message_around: Some(id.to_string()),
                    message_limit: Some(1),
                    ..Default::default()
                },
            ) {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(%error, "permission review context lookup failed");
                    None
                }
            }
        });
    let ordinary_user_request = session
        .as_ref()
        .and_then(|session| session.messages.first())
        .filter(|message| {
            user_message_id.as_deref() == Some(message.id.as_str()) && message.role == "user"
        })
        .map(|message| message.content.as_str())
        .unwrap_or("");
    let approved_context = approved_execution_context(&st, &request.session_id, turn_id.as_deref());
    let (user_request, approved_plan, plan_context_complete) = match approved_context {
        Ok(Some((origin, plan))) => (origin, Some(plan), true),
        Ok(None) => (ordinary_user_request.to_string(), None, true),
        Err(()) => (String::new(), None, false),
    };
    let arg_text = serde_json::to_string(&request.args_preview).unwrap_or_default();
    let content_complete = plan_context_complete
        && approved_plan
            .as_deref()
            .is_none_or(|plan| review_evidence_safe(plan, 4_000))
        && context_complete(
            &user_request,
            &arg_text,
            turn_id
                .as_deref()
                .is_some_and(|id| running_turn(&st, &request.session_id, id))
                && workspace_path
                    .as_deref()
                    .is_some_and(|path| !path.is_empty()),
        );
    let permission_mode = &request.permission_mode;
    let workspace = workspace_path.as_deref().unwrap_or("");
    let mut action = json!({
        "userRequest": if content_complete { user_request.as_str() } else { "" },
        "toolName": request.tool_name,
        "arguments": if content_complete { request.args_preview } else { Value::Null },
        "workspace": workspace,
        "workingDirectory": workspace,
        "permissionMode": permission_mode,
        "isolation": "No OS shell or plugin capability sandbox",
        "complete": content_complete,
    });
    if let Some(policy) = configured_policy {
        action["policyPrompt"] = policy;
    }
    if content_complete {
        if let Some(approved_plan) = approved_plan.as_deref() {
            action["approvedPlan"] = json!(approved_plan);
        }
    }
    st.permissions
        .set_review_context_complete(request_id, &token, content_complete);
    Ok(json!({ "token": token, "fingerprint": fingerprint, "action": action }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    #[test]
    fn native_secret_target_is_denied_before_review() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().to_str().unwrap();
        assert!(sensitive_native_target(
            "Read",
            &json!({"path": ".env.local"}),
            Some(dir),
            None
        ));
        assert!(sensitive_native_target(
            "Write",
            &json!({"path": "private.pem"}),
            Some(dir),
            None
        ));
        assert!(sensitive_native_target(
            "Edit",
            &json!({"path": "safe.txt", "ops": "[safe.txt#AAAA]\nMV .env.local"}),
            Some(dir),
            None
        ));
        assert!(!sensitive_native_target(
            "Read",
            &json!({"path": "result.txt"}),
            Some(dir),
            None
        ));
    }

    #[test]
    fn sensitive_or_unbound_evidence_never_enters_model_review() {
        let safe = "Create result.txt with approved content";
        let args = r#"{"path":"result.txt","content":"approved"}"#;
        assert!(context_complete(safe, args, true));
        let windows_path = r"C:\Users\win\Desktop\project\result.txt";
        let windows_args = json!({"path": windows_path, "content": "approved"}).to_string();
        assert!(context_complete(
            &format!("Edit {windows_path} as requested"),
            &windows_args,
            true,
        ));
        assert!(context_complete(
            "Edit /tmp/project/result.txt as requested",
            &json!({"path": "/tmp/project/result.txt"}).to_string(),
            true,
        ));
        assert!(!context_complete(safe, args, false));
        assert!(!context_complete(
            "Send ghp_12345678 to my address",
            args,
            true
        ));
        assert!(!context_complete(
            safe,
            r#"{"api_key":"secret_value"}"#,
            true
        ));
        assert!(!context_complete(safe, r#"{"token":"abc123"}"#, true));
        assert!(!context_complete(
            safe,
            r#"{"access_token":"abc123"}"#,
            true
        ));
        assert!(!context_complete(
            safe,
            r#"{"path":"fixture","body":"Bearer token"}"#,
            true
        ));
        assert!(!context_complete(safe, &"x".repeat(8_001), true));
        assert!(!context_complete(safe, "… (+3000 chars)", true));
        assert!(!context_complete(safe, "…[truncated]", true));
        assert!(review_evidence_safe(
            "# Plan\nEdit C:\\Users\\win\\Desktop\\project\\file.txt and /tmp/file.txt",
            4_000,
        ));
        assert!(!review_evidence_safe("# Plan\ntoken=abc123", 4_000));
        assert!(!context_complete(safe, r#"{"value":"token=abc123"}"#, true));
        assert!(!context_complete(
            "Use https://reader:pass123@example.com/feed for this task",
            args,
            true,
        ));
    }

    #[tokio::test]
    async fn configuring_one_session_does_not_cancel_another_sessions_permission() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        app.handshook = true;
        let first = sessions::create_session(
            &app.db,
            Some("A".into()),
            Some("agent".into()),
            None,
            None,
            Some(project.to_string_lossy().into_owned()),
        )
        .unwrap();
        let second = sessions::create_session(
            &app.db,
            Some("B".into()),
            Some("agent".into()),
            None,
            None,
            Some(project.to_string_lossy().into_owned()),
        )
        .unwrap();
        let state = Arc::new(Mutex::new(app));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut tasks = Vec::new();
        for (session, filename) in [(first.id.clone(), "a.txt"), (second.id.clone(), "b.txt")] {
            let state = state.clone();
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                handle_request(state, "tools.execute", json!({
                "sessionId": session, "toolCallId": filename, "toolName": "Write", "mode": "agent",
                "args": {"path": filename, "content": "authorized"}
            }), tx).await
            }));
        }
        let mut request_ids = HashMap::new();
        while request_ids.len() < 2 {
            let note = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .unwrap()
                .unwrap();
            let frame: Value = serde_json::from_str(&note).unwrap();
            if frame["method"] == "permissions.request" {
                request_ids.insert(
                    frame["params"]["sessionId"].as_str().unwrap().to_owned(),
                    frame["params"]["requestId"].as_str().unwrap().to_owned(),
                );
            }
        }
        handle_request(state.clone(), "session.configure", json!({
            "id": first.id, "mode": "agent", "approvalReviewer": "user", "permissionMode": "auto",
        }), tx.clone()).await.unwrap();
        assert!(handle_request(
            state.clone(),
            "permissions.pending",
            json!({
                "sessionId": second.id,
            }),
            tx.clone()
        )
        .await
        .unwrap()["requests"]
            .as_array()
            .is_some_and(|requests| requests.len() == 1));
        handle_request(
            state.clone(),
            "permissions.resolve",
            json!({
                "requestId": request_ids[&second.id], "decision": "allow-once"
            }),
            tx,
        )
        .await
        .unwrap();
        let a = tasks.remove(0).await.unwrap().unwrap();
        let b = tasks.remove(0).await.unwrap().unwrap();
        assert_eq!(a["ok"], false);
        assert_eq!(b["ok"], true);
        assert!(!project.join("a.txt").exists());
        assert_eq!(
            fs::read_to_string(project.join("b.txt")).unwrap(),
            "authorized"
        );
    }

    #[tokio::test]
    async fn reviewer_disconnect_notifies_manual_fallback_and_rejects_stale_result() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        app.handshook = true;
        app.review_executor_available = true;
        let (request, _receiver) = app.permissions.create_request_with_risk_and_shell(
            crate::permissions::PermissionRequestParams {
                session_id: "test",
                tool_call_id: "call",
                tool_name: "Write",
                args_preview: json!({"path": "out.txt"}),
                reason: "writes a file",
                declared_risk: None,
                command_shell_id: None,
                review_state: "awaiting_review",
                scope_label: None,
                turn_id: None,
                user_message_id: None,
                permission_mode: "ask",
                workspace_path: None,
            },
        );
        app.permissions
            .bind_action(&request.request_id, "fingerprint");
        let (token, _, fingerprint, _, _, _) =
            app.permissions.claim_review(&request.request_id).unwrap();
        let state = Arc::new(Mutex::new(app));
        let (tx, mut rx) = mpsc::unbounded_channel();
        handle_request(
            state.clone(),
            "permissions.setReviewCapability",
            json!({"available": false}),
            tx,
        )
        .await
        .unwrap();
        let notification: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(notification["method"], "permissions.reviewUpdated");
        assert_eq!(notification["params"]["requestId"], request.request_id);
        assert_eq!(notification["params"]["reviewState"], "user");
        assert_eq!(
            state
                .lock()
                .await
                .permissions
                .review_state(&request.request_id),
            Some("user")
        );
        assert!(state
            .lock()
            .await
            .permissions
            .resolve_review(&request.request_id, &token, &fingerprint, "allow_once")
            .is_err());
    }

    #[tokio::test]
    async fn desktop_permit_admission_has_a_finite_quota() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        let generation = app.permissions.generation("session");
        for index in 0..crate::permissions::permits::MAX_OUTSTANDING_PERMITS {
            app.plugin_execution_permits.insert(
                index.to_string(),
                ExecutionPermit::new(
                    "session",
                    None,
                    "call",
                    "plugin_test_run",
                    &json!({}),
                    generation,
                    "scope",
                    "agent",
                    false,
                ),
            );
        }
        let state = Arc::new(Mutex::new(app));
        let (tx, mut notifications) = mpsc::unbounded_channel();
        let params: ToolsExecuteParams = serde_json::from_value(json!({
            "sessionId": "session", "toolCallId": "new", "toolName": "plugin_test_run",
            "mode": "agent", "args": {}, "timeoutMs": 1000,
        }))
        .unwrap();
        let outcome = execute_plugin_tool(
            &state, &tx, &params, 1000, "agent", generation, None, "agent", false,
        )
        .await;
        assert_eq!(outcome.error_code.as_deref(), Some("AGENT_BUSY"));
        assert!(notifications.try_recv().is_err());
    }

    #[tokio::test]
    async fn execution_permit_rpc_is_single_use_and_rechecks_scope() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        app.handshook = true;
        let session = sessions::create_session(
            &app.db,
            Some("permit".into()),
            Some("agent".into()),
            None,
            None,
            Some(project.to_string_lossy().into_owned()),
        )
        .unwrap();
        let session_id = session.id;
        let args = json!({"path": "out.txt", "content": "write"});
        let (_, scope, _) =
            grants::action_scope("Write", &args, Some(&project), None, None, None).unwrap();
        let generation = app.permissions.generation(&session_id);
        let permit = ExecutionPermit::new(
            &session_id,
            None,
            "call",
            "Write",
            &args,
            generation,
            &scope,
            "agent",
            false,
        );
        let token = permit.token.clone();
        let (sender, _receiver) = oneshot::channel();
        app.plugin_execs.insert("exec".into(), sender);
        app.plugin_execution_permits.insert("exec".into(), permit);
        let state = Arc::new(Mutex::new(app));
        let (tx, _) = mpsc::unbounded_channel();
        let input = json!({"executionId": "exec", "permitToken": token,
            "sessionId": session_id, "toolCallId": "call", "toolName": "Write", "args": args});
        let mut changed = input.clone();
        changed["args"]["path"] = json!("other.txt");
        assert!(handle_request(
            state.clone(),
            "permissions.consumeExecutionPermit",
            changed,
            tx.clone()
        )
        .await
        .is_err());
        // An invalid consume burns the permit rather than allowing a later replay.
        assert!(handle_request(
            state.clone(),
            "permissions.consumeExecutionPermit",
            input.clone(),
            tx.clone()
        )
        .await
        .is_err());
        let (_, scope, _) =
            grants::action_scope("Write", &input["args"], Some(&project), None, None, None)
                .unwrap();
        state.lock().await.plugin_execution_permits.insert(
            "exec".into(),
            ExecutionPermit::new(
                &session_id,
                None,
                "call",
                "Write",
                &input["args"],
                generation,
                &scope,
                "agent",
                false,
            ),
        );
        let token = state.lock().await.plugin_execution_permits["exec"]
            .token
            .clone();
        let mut valid = input;
        valid["permitToken"] = json!(token);
        assert_eq!(
            handle_request(
                state.clone(),
                "permissions.consumeExecutionPermit",
                valid.clone(),
                tx.clone()
            )
            .await
            .unwrap()["ok"],
            true
        );
        assert!(
            handle_request(state, "permissions.consumeExecutionPermit", valid, tx)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn pathless_session_review_snapshot_uses_authoritative_scratch_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        let session = sessions::create_session(
            &app.db,
            Some("temporary".into()),
            Some("agent".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let workspace =
            resolve_tool_workspace_for_call(&app, &session.id, &json!({"path": "out.txt"}))
                .unwrap()
                .unwrap();
        assert!(workspace.contains("scratch"));
        let (request, _receiver) = app.permissions.create_request_with_risk_and_shell(
            crate::permissions::PermissionRequestParams {
                session_id: &session.id,
                tool_call_id: "call",
                tool_name: "Write",
                args_preview: json!({"path": "out.txt"}),
                reason: "writes a file",
                declared_risk: None,
                command_shell_id: None,
                review_state: "awaiting_review",
                scope_label: None,
                turn_id: None,
                user_message_id: None,
                permission_mode: "ask",
                workspace_path: Some(&workspace),
            },
        );
        app.permissions
            .bind_action(&request.request_id, "fingerprint");
        let state = Arc::new(Mutex::new(app));
        let (tx, _) = mpsc::unbounded_channel();
        let action = claim(&state, &json!({"requestId": request.request_id}), &tx)
            .await
            .unwrap()["action"]
            .clone();
        assert_eq!(action["workspace"], workspace);
        assert_eq!(action["workingDirectory"], workspace);
        assert_eq!(action["complete"], false);
        assert!(action["userRequest"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sidecar_cannot_forge_plugin_risk_or_plan_exemption() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        app.handshook = true;
        let session = sessions::create_session(
            &app.db,
            Some("plugin".into()),
            Some("agent".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let state = Arc::new(Mutex::new(app));
        let (tx, _) = mpsc::unbounded_channel();
        let input = json!({"sessionId": session.id, "toolName": "plugin_absent_send",
            "declaredRisk": "low", "planSafeActions": ["send"], "args": {"action": "send"}});
        let evaluated = handle_request(
            state.clone(),
            "permissions.evaluate",
            input.clone(),
            tx.clone(),
        )
        .await
        .unwrap();
        assert_eq!(evaluated["risk"], "medium");
        assert!(evaluated["decision"].is_null());
        sessions::configure_session_with_thinking(
            &state.lock().await.db,
            &session.id,
            "plan",
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let evaluated = handle_request(state, "permissions.evaluate", input, tx)
            .await
            .unwrap();
        assert_eq!(evaluated["decision"], "deny");
    }

    #[test]
    fn approved_plan_context_is_bound_to_verified_artifact_and_original_request() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("project");
        fs::create_dir_all(&workspace).unwrap();
        let app = AppState::open(dir.path()).unwrap();
        let session = sessions::create_session(
            &app.db,
            Some("plan".into()),
            Some("plan".into()),
            None,
            None,
            Some(workspace.to_string_lossy().into_owned()),
        )
        .unwrap();
        let plan_turn = sessions::begin_turn(&app.db, &session.id, None, None).unwrap();
        let original: sessions::UiMessage = serde_json::from_value(json!({
            "id": "user-request", "role": "user", "content": "Build the API endpoint",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }))
        .unwrap();
        sessions::append_message(&app.db, &session.id, &original, Some(&plan_turn)).unwrap();
        let proposal = app
            .plans
            .submit(
                &app.db,
                plans::PlanSubmitParams {
                    workspace_root: &workspace,
                    session_id: &session.id,
                    turn_id: &plan_turn,
                    tool_call_id: "submit-plan",
                    kind: plans::KIND_PLAN,
                    title: "Build API",
                    markdown: "# Plan\n- implement endpoint",
                    question: "Proceed?",
                },
            )
            .unwrap();
        sessions::end_turn(&app.db, &plan_turn, "completed", None, None, false).unwrap();
        let resolution = app
            .plans
            .resolve(
                &app.db,
                plans::PlanResolveParams {
                    workspace_root: Some(&workspace),
                    proposal_id: &proposal.id,
                    session_id: &session.id,
                    turn_id: &plan_turn,
                    tool_call_id: "submit-plan",
                    version: Some(proposal.version),
                    action: "approve",
                    target_permission_mode: Some("ask"),
                },
            )
            .unwrap();
        app.plans
            .claim_execution(&app.db, &resolution.execution.unwrap().id)
            .unwrap();
        let execution_turn = sessions::begin_turn(&app.db, &session.id, None, None).unwrap();
        let unrelated: sessions::UiMessage = serde_json::from_value(json!({
            "id": "unrelated", "role": "user", "content": "Delete unrelated files",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }))
        .unwrap();
        sessions::append_message(&app.db, &session.id, &unrelated, Some(&execution_turn)).unwrap();
        let context = approved_execution_context(&app, &session.id, Some(&execution_turn))
            .unwrap()
            .unwrap();
        assert_eq!(context.0, "Build the API endpoint");
        assert_eq!(context.1, "# Plan\n- implement endpoint");
        let artifact = proposal.artifact.unwrap();
        fs::write(workspace.join(artifact.relative_path), "tampered").unwrap();
        assert!(approved_execution_context(&app, &session.id, Some(&execution_turn)).is_err());
    }

    #[tokio::test]
    async fn invalid_stored_policy_cannot_be_claimed_or_approved_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        app.handshook = true;
        let session = sessions::create_session(
            &app.db,
            Some("review".into()),
            Some("agent".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let turn = sessions::begin_turn(&app.db, &session.id, None, None).unwrap();
        let make_request = |st: &mut AppState, tool_call_id: &str| {
            let (request, _receiver) = st.permissions.create_request_with_risk_and_shell(
                crate::permissions::PermissionRequestParams {
                    session_id: &session.id,
                    tool_call_id,
                    tool_name: "Write",
                    args_preview: json!({"path":"out.txt"}),
                    reason: "writes a file",
                    declared_risk: None,
                    command_shell_id: None,
                    review_state: "awaiting_review",
                    scope_label: None,
                    turn_id: Some(&turn),
                    user_message_id: None,
                    permission_mode: "ask",
                    workspace_path: None,
                },
            );
            st.permissions
                .bind_action(&request.request_id, "fingerprint");
            request.request_id
        };
        app.db
            .set_setting("app", &json!({"autoReview":{"policyPrompt":false}}))
            .unwrap();
        let first_id = make_request(&mut app, "claim-invalid");
        let state = Arc::new(Mutex::new(app));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let error = claim(&state, &json!({"requestId":first_id}), &tx)
            .await
            .unwrap_err();
        assert_eq!(error.data.unwrap()["errorCode"], "REVIEW_NOT_AVAILABLE");
        assert_eq!(
            state.lock().await.permissions.review_state(&first_id),
            Some("user")
        );
        let notified: Value = serde_json::from_str(&rx.recv().await.unwrap()).unwrap();
        assert_eq!(notified["params"]["reviewState"], "user");

        let second_id = {
            let mut st = state.lock().await;
            st.db
                .set_setting(
                    "app",
                    &json!({"autoReview":{"policyPrompt":"Ask for edits"}}),
                )
                .unwrap();
            make_request(&mut st, "resolve-invalid")
        };
        let claimed = claim(&state, &json!({"requestId":second_id}), &tx)
            .await
            .unwrap();
        assert_eq!(claimed["action"]["policyPrompt"], "Ask for edits");
        state
            .lock()
            .await
            .db
            .set_setting("app", &json!({"autoReview":{"policyPrompt":" \n "}}))
            .unwrap();
        let error = resolve(
            &state,
            &json!({
                "requestId":second_id,
                "token":claimed["token"],
                "fingerprint":claimed["fingerprint"],
                "result":{"decision":"allow_once", "risk":"low", "authorization":"explicit",
                    "reason":"Requested", "policyVersion":"1"},
            }),
            &tx,
        )
        .await
        .unwrap_err();
        assert_eq!(error.data.unwrap()["errorCode"], "REVIEW_NOT_AVAILABLE");
        assert_eq!(
            state.lock().await.permissions.review_state(&second_id),
            Some("user")
        );
    }

    #[tokio::test]
    async fn unicode_reason_limit_counts_characters_not_utf8_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = AppState::open(dir.path()).unwrap();
        app.handshook = true;
        let saved_policy = "Ask before changing files. 🔒";
        app.db
            .set_setting("app", &json!({"autoReview":{"policyPrompt":saved_policy}}))
            .unwrap();
        let session = sessions::create_session(
            &app.db,
            Some("review".into()),
            Some("agent".into()),
            None,
            None,
            None,
        )
        .unwrap();
        let turn = sessions::begin_turn(&app.db, &session.id, None, None).unwrap();
        let (request, _receiver) = app.permissions.create_request_with_risk_and_shell(
            crate::permissions::PermissionRequestParams {
                session_id: &session.id,
                tool_call_id: "call",
                tool_name: "Write",
                args_preview: json!({"path":"file"}),
                reason: "write",
                declared_risk: None,
                command_shell_id: None,
                review_state: "awaiting_review",
                scope_label: None,
                turn_id: Some(&turn),
                user_message_id: None,
                permission_mode: "ask",
                workspace_path: None,
            },
        );
        app.permissions
            .bind_action(&request.request_id, "fingerprint");
        let (token, _, fingerprint, _, _, _) =
            app.permissions.claim_review(&request.request_id).unwrap();
        app.permissions
            .set_review_context_complete(&request.request_id, &token, true);
        let state = Arc::new(Mutex::new(app));
        let (tx, _) = mpsc::unbounded_channel();
        let outcome = resolve(
            &state,
            &json!({"requestId": request.request_id,
            "token": token, "fingerprint": fingerprint,
            "result": {"decision":"allow_once", "risk":"low", "authorization":"explicit",
                "policyVersion":"1", "reason": "已".repeat(150)}}),
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(outcome["decision"], "allow_once");
        let audit_payload: String = state.lock().await.db.conn().query_row(
            "SELECT payload_json FROM audit_log WHERE kind = 'permission_review' ORDER BY id DESC LIMIT 1",
            [], |row| row.get(0)).unwrap();
        assert!(!audit_payload.contains(saved_policy));
        let expected_identity = format!(
            "custom-sha256:{}",
            grants::fingerprint(&json!(saved_policy))
        );
        let audit_value: Value = serde_json::from_str(&audit_payload).unwrap();
        assert_eq!(audit_value["policyIdentity"], expected_identity);
    }
}

pub(super) async fn resolve(
    state: &Arc<Mutex<AppState>>,
    params: &Value,
    tx: &mpsc::UnboundedSender<String>,
) -> Result<Value, JsonRpcError> {
    let request_id = params
        .get("requestId")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(1002, "requestId required", "INVALID_PARAMS"))?;
    let token = params
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(1002, "token required", "INVALID_PARAMS"))?;
    let fingerprint = params
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(1002, "fingerprint required", "INVALID_PARAMS"))?;
    let result = params
        .get("result")
        .ok_or_else(|| rpc_err(1002, "result required", "INVALID_PARAMS"))?;
    let proposed = result.get("decision").and_then(Value::as_str);
    let risk = result.get("risk").and_then(Value::as_str);
    let authorization = result.get("authorization").and_then(Value::as_str);
    let policy = result.get("policyVersion").and_then(Value::as_str);
    let reason = result
        .get("reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.trim().is_empty() && reason.chars().count() <= 300)
        .unwrap_or("Automated review returned an invalid decision.");
    let valid = matches!(proposed, Some("allow_once" | "deny" | "needs_user"))
        && matches!(risk, Some("low" | "medium" | "high"))
        && matches!(authorization, Some("explicit" | "absent" | "uncertain"))
        && policy == Some("1")
        && result.get("reason").and_then(Value::as_str) == Some(reason);
    let candidate = if valid
        && !(proposed == Some("allow_once")
            && (risk == Some("high") || authorization != Some("explicit")))
    {
        proposed.unwrap_or("needs_user")
    } else {
        "needs_user"
    };
    let mut st = state.lock().await;
    let stored_settings = st
        .db
        .get_setting("app")
        .map_err(|error| rpc_err(1000, error.to_string(), "INTERNAL"))?;
    let configured_policy = stored_settings
        .as_ref()
        .and_then(|settings| settings.get("autoReview"))
        .and_then(|binding| binding.get("policyPrompt"));
    if configured_policy.is_some_and(|policy| !valid_review_policy(policy)) {
        st.permissions
            .takeover_review(request_id)
            .map_err(|error| rpc_err(1008, error.clone(), &error))?;
        emit_notification(
            tx,
            "permissions.reviewUpdated",
            json!({
                "requestId": request_id, "reviewState": "user",
                "reason": "Review policy is invalid; human approval is required",
            }),
        )
        .await;
        return Err(rpc_err(
            1008,
            "review policy is invalid",
            "REVIEW_NOT_AVAILABLE",
        ));
    }
    let policy_identity = configured_policy.map_or_else(
        || "default-v1".to_string(),
        |prompt| format!("custom-sha256:{}", grants::fingerprint(prompt)),
    );
    let session_id = st
        .permissions
        .review_session_id(request_id)
        .map(str::to_string);
    let turn_id = st
        .permissions
        .review_turn_id(request_id)
        .map(str::to_string);
    let still_running = turn_id.as_deref().is_some_and(|id| {
        session_id
            .as_deref()
            .is_some_and(|session| running_turn(&st, session, id))
    });
    let candidate = if still_running {
        candidate
    } else {
        "needs_user"
    };
    let details = st.permissions.review_details(request_id);
    let decision = st
        .permissions
        .resolve_review(request_id, token, fingerprint, candidate)
        .map_err(|error| rpc_err(1008, error.clone(), &error))?;
    if decision != "needs_user" {
        st.clear_pending_permission(request_id);
    }
    let safe_model = |key: &str| {
        result
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.chars().count() <= 200)
    };
    let usage = permission_review_history::safe_usage(result);
    if let Err(error) = audit::append(
        &st.db,
        "permission_review",
        session_id.as_deref(),
        json!({
            "requestId": request_id, "decision": decision, "risk": risk,
            "authorization": authorization, "reason": reason, "policyVersion": policy,
            "policyIdentity": policy_identity,
            "fingerprint": fingerprint, "usage": usage,
            "toolCallId": details.as_ref().map(|(request, _, _)| request.tool_call_id.as_str()),
            "toolName": details.as_ref().map(|(request, _, _)| request.tool_name.as_str()),
            "latencyMs": details.as_ref().map(|(_, latency, _)| latency),
            "actorId": details.as_ref().and_then(|(_, _, actor)| actor.as_deref()),
            "decisionSource": "auto_review",
            "reviewerProviderId": safe_model("reviewerProviderId"),
            "reviewerModelId": safe_model("reviewerModelId"),
        }),
    ) {
        tracing::warn!(%error, "permission review audit failed");
    }
    if decision == "needs_user" {
        emit_notification(
            tx,
            "permissions.reviewUpdated",
            json!({
                "requestId": request_id, "reviewState": "user", "reason": reason,
            }),
        )
        .await;
    }
    Ok(json!({ "ok": true, "decision": decision }))
}

pub(super) async fn takeover(
    state: &Arc<Mutex<AppState>>,
    params: &Value,
    tx: &mpsc::UnboundedSender<String>,
) -> Result<Value, JsonRpcError> {
    let request_id = params
        .get("requestId")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(1002, "requestId required", "INVALID_PARAMS"))?;
    let mut st = state.lock().await;
    st.permissions
        .takeover_review(request_id)
        .map_err(|error| rpc_err(1008, error.clone(), &error))?;
    emit_notification(
        tx,
        "permissions.reviewUpdated",
        json!({
            "requestId": request_id, "reviewState": "user", "reason": "Reviewer taken over by user",
        }),
    )
    .await;
    Ok(json!({ "ok": true }))
}
