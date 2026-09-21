#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(sys.argv[1]).resolve()
HERE = Path(__file__).resolve().parent

def read(rel): return (ROOT/rel).read_text()
def write(rel, s):
    p=ROOT/rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(s)
def rep(s, old, new, label):
    n=s.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly 1 anchor, found {n}")
    return s.replace(old,new,1)

write('crates/openshell-supervisor-network/src/durable_egress.rs', (HERE/'durable_egress.rs').read_text())
p='crates/openshell-supervisor-network/src/lib.rs'; s=read(p)
s=rep(s, 'pub mod identity;\n', 'pub mod durable_egress;\npub mod identity;\n', 'network lib module')
write(p,s)

p='crates/openshell-supervisor-process/src/supervisor_session.rs'; s=read(p)
s=rep(s,
'''const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Runtime identity and status channel shared with a supervisor session task.''',
'''const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub type SessionIdHook = Arc<dyn Fn(Option<String>) + Send + Sync>;

/// Runtime identity and status channel shared with a supervisor session task.''',
'session hook alias')
s=rep(s,
'''    /// Publishes the currently accepted gateway session to sibling reporters.
    pub session_id_updates: Option<watch::Sender<Option<String>>>,
}''',
'''    /// Publishes the currently accepted gateway session to sibling reporters.
    pub session_id_updates: Option<watch::Sender<Option<String>>>,
    /// Synchronous authority hook used to linearize egress dispatch with session replacement.
    pub session_id_hook: Option<SessionIdHook>,
}''',
'session runtime hook field')
s=rep(s,
'''        instance_id: runtime.instance_id,
        session_id_updates: runtime.session_id_updates,
        ready_tx,''',
'''        instance_id: runtime.instance_id,
        session_id_updates: runtime.session_id_updates,
        session_id_hook: runtime.session_id_hook,
        ready_tx,''',
'session config construction')
s=rep(s,
'''    /// Publishes the currently accepted session to sibling control-plane reporters.
    session_id_updates: Option<watch::Sender<Option<String>>>,
    ready_tx: watch::Sender<bool>,''',
'''    /// Publishes the currently accepted session to sibling control-plane reporters.
    session_id_updates: Option<watch::Sender<Option<String>>>,
    session_id_hook: Option<SessionIdHook>,
    ready_tx: watch::Sender<bool>,''',
'session config hook field')
s=rep(s,
'''        let result = run_single_session(&config).await;
        if let Some(updates) = &config.session_id_updates {
            updates.send_replace(None);
        }''',
'''        let result = run_single_session(&config).await;
        if let Some(hook) = &config.session_id_hook {
            hook(None);
        }
        if let Some(updates) = &config.session_id_updates {
            updates.send_replace(None);
        }''',
'session clear hook')
s=rep(s,
'''    if let Some(updates) = &config.session_id_updates {
        updates.send_replace(Some(accepted.session_id.clone()));
    }''',
'''    if let Some(hook) = &config.session_id_hook {
        hook(Some(accepted.session_id.clone()));
    }
    if let Some(updates) = &config.session_id_updates {
        updates.send_replace(Some(accepted.session_id.clone()));
    }''',
'session accepted hook')
write(p,s)

p='crates/openshell-supervisor-process/src/delegated.rs'; s=read(p)
s=rep(s,
'''    agent: Arc<dyn BoundaryProcess>,
    supervisor_session_updates: Option<tokio::sync::watch::Sender<Option<String>>>,
) -> Result<BoundaryAccess> {''',
'''    agent: Arc<dyn BoundaryProcess>,
    supervisor_session_updates: Option<tokio::sync::watch::Sender<Option<String>>>,
    supervisor_session_hook: Option<crate::supervisor_session::SessionIdHook>,
) -> Result<BoundaryAccess> {''',
'delegated hook arg')
s=rep(s,
'''                    instance_id: instance_id.clone(),
                    session_id_updates: supervisor_session_updates,
                },''',
'''                    instance_id: instance_id.clone(),
                    session_id_updates: supervisor_session_updates,
                    session_id_hook: supervisor_session_hook,
                },''',
'delegated runtime hook')
write(p,s)

p='crates/openshell-supervisor/src/lib.rs'; s=read(p)
s=rep(s,
'''            Some(supervisor_session_updates),
        )
        .await?;''',
'''            Some(supervisor_session_updates),
            Some(Arc::new(|session| {
                openshell_supervisor_network::durable_egress::publish_supervisor_session(session);
            })),
        )
        .await?;''',
'supervisor boundary hook')
write(p,s)

p='crates/openshell-supervisor-network/src/run.rs'; s=read(p)
s=rep(s,
'''    let proxy_handle = if matches!(policy.network.mode, NetworkMode::Proxy) {''',
'''    let durable_egress_gate = crate::durable_egress::gate_from_env(sandbox_id)?;

    let proxy_handle = if matches!(policy.network.mode, NetworkMode::Proxy) {''',
'run gate construction')
s=s.replace('let proxy_handle = ProxyHandle::start_with_bind_addr(\n', 'let proxy_handle = ProxyHandle::start_with_bind_addr_with_gate(\n', 1)
s=rep(s,
'''            None,
        )
        .await?;''',
'''            None,
            durable_egress_gate.clone(),
        )
        .await?;''',
'run proxy gate argument')
s=rep(s,
'''            upstream_proxy_args,
            transparent_engine_ready_rx,
        )?;''',
'''            upstream_proxy_args,
            transparent_engine_ready_rx,
            durable_egress_gate,
        )?;''',
'transparent gate argument')
write(p,s)

p='crates/openshell-supervisor-network/src/proxy.rs'; s=read(p)
s=rep(s,
'''use crate::identity::BinaryIdentityCache;''',
'''use crate::durable_egress::{DurableEgressPermitGate, EgressSurface, PermitInput};
use crate::identity::BinaryIdentityCache;''',
'proxy gate imports')

old='''    pub(crate) async fn start_with_bind_addr(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
        opa_engine: Arc<OpaEngine>,
        identity_cache: Arc<BinaryIdentityCache>,
        entrypoint_pid: Arc<AtomicU32>,
        tls_state: Option<Arc<ProxyTlsState>>,
        provider_credentials: Option<ProviderCredentialState>,
        policy_local_ctx: Option<Arc<PolicyLocalContext>>,
        denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
        activity_tx: Option<ActivitySender>,
        endpoint_observation_tx: Option<EndpointObservationSender>,
        engine_ready: tokio::sync::watch::Receiver<bool>,
        upstream_proxy_args: &upstream_proxy::UpstreamProxyArgs,
        backend_host_gateway: Option<IpAddr>,
        network_mediation_source: Option<Arc<dyn NetworkMediationSource>>,
        policy_dns_store: Option<Arc<ResolvedEndpointStore>>,
        direct_listener_identity: Option<ContractBinaryIdentity>,
    ) -> Result<Self> {'''
new='''    pub(crate) async fn start_with_bind_addr_with_gate(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
        opa_engine: Arc<OpaEngine>,
        identity_cache: Arc<BinaryIdentityCache>,
        entrypoint_pid: Arc<AtomicU32>,
        tls_state: Option<Arc<ProxyTlsState>>,
        provider_credentials: Option<ProviderCredentialState>,
        policy_local_ctx: Option<Arc<PolicyLocalContext>>,
        denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
        activity_tx: Option<ActivitySender>,
        endpoint_observation_tx: Option<EndpointObservationSender>,
        engine_ready: tokio::sync::watch::Receiver<bool>,
        upstream_proxy_args: &upstream_proxy::UpstreamProxyArgs,
        backend_host_gateway: Option<IpAddr>,
        network_mediation_source: Option<Arc<dyn NetworkMediationSource>>,
        policy_dns_store: Option<Arc<ResolvedEndpointStore>>,
        direct_listener_identity: Option<ContractBinaryIdentity>,
        durable_egress_gate: Option<Arc<DurableEgressPermitGate>>,
    ) -> Result<Self> {'''
s=rep(s,old,new,'proxy gated start signature')
marker='''    pub(crate) async fn start_with_bind_addr_with_gate(
'''
wrapper='''    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start_with_bind_addr(
        policy: &ProxyPolicy,
        bind_addr: Option<SocketAddr>,
        opa_engine: Arc<OpaEngine>,
        identity_cache: Arc<BinaryIdentityCache>,
        entrypoint_pid: Arc<AtomicU32>,
        tls_state: Option<Arc<ProxyTlsState>>,
        provider_credentials: Option<ProviderCredentialState>,
        policy_local_ctx: Option<Arc<PolicyLocalContext>>,
        denial_tx: Option<mpsc::UnboundedSender<DenialEvent>>,
        activity_tx: Option<ActivitySender>,
        endpoint_observation_tx: Option<EndpointObservationSender>,
        engine_ready: tokio::sync::watch::Receiver<bool>,
        upstream_proxy_args: &upstream_proxy::UpstreamProxyArgs,
        backend_host_gateway: Option<IpAddr>,
        network_mediation_source: Option<Arc<dyn NetworkMediationSource>>,
        policy_dns_store: Option<Arc<ResolvedEndpointStore>>,
        direct_listener_identity: Option<ContractBinaryIdentity>,
    ) -> Result<Self> {
        Self::start_with_bind_addr_with_gate(
            policy, bind_addr, opa_engine, identity_cache, entrypoint_pid, tls_state,
            provider_credentials, policy_local_ctx, denial_tx, activity_tx,
            endpoint_observation_tx, engine_ready, upstream_proxy_args,
            backend_host_gateway, network_mediation_source, policy_dns_store,
            direct_listener_identity, None,
        ).await
    }

'''
s=s.replace(marker,wrapper+marker,1)

s=rep(s,
'''                        let endpoint_observations = endpoint_observation_tx.clone();
                        tokio::spawn(async move {''',
'''                        let endpoint_observations = endpoint_observation_tx.clone();
                        let blackbox_gate = durable_egress_gate.clone();
                        tokio::spawn(async move {''',
'proxy clone gate')
s=rep(s,
'''                                atx,
                                endpoint_observations,
                            )''',
'''                                atx,
                                endpoint_observations,
                                blackbox_gate,
                            )''',
'proxy handler gate arg')

s=rep(s,
'''    activity_tx: Option<ActivitySender>,
    endpoint_observation_tx: Option<EndpointObservationSender>,
) -> Result<()> {
    // Bind observations''',
'''    activity_tx: Option<ActivitySender>,
    endpoint_observation_tx: Option<EndpointObservationSender>,
    durable_egress_gate: Option<Arc<DurableEgressPermitGate>>,
) -> Result<()> {
    let blackbox_transparent = transparent_open.is_some();
    // Bind observations''',
'mediated handler gate signature')
s=rep(s,
'''        activity_tx,
        endpoint_observation_tx,
    ))
    .await
}''',
'''        activity_tx,
        endpoint_observation_tx,
        None,
    ))
    .await
}''',
'test helper mediated None')

forward_sig='''async fn handle_forward_proxy(
    method: &str,
    target_uri: &str,
    buf: &[u8],
    used: usize,
    client: &mut ProxyClient,
    supplied_identity: Option<&Result<ContractBinaryIdentity, ResolveError>>,
    socket_addrs: Option<(SocketAddr, SocketAddr)>,
    opa_engine: Arc<OpaEngine>,
    identity_cache: Arc<BinaryIdentityCache>,
    entrypoint_pid: Arc<AtomicU32>,
    policy_local_ctx: Option<Arc<PolicyLocalContext>>,
    agent_proposals: openshell_core::proposals::AgentProposals,
    backend_host_gateway: Arc<Option<IpAddr>>,
    trusted_host_gateway: Arc<Option<IpAddr>>,
    provider_credentials: Option<ProviderCredentialState>,
    secret_resolver: Option<Arc<SecretResolver>>,
    dynamic_credentials: Option<
        Arc<
            std::sync::RwLock<
                std::collections::HashMap<String, openshell_core::proto::ProviderProfileCredential>,
            >,
        >,
    >,
    denial_tx: Option<&mpsc::UnboundedSender<DenialEvent>>,
    activity_tx: Option<&ActivitySender>,
    endpoint_observation_tx: Option<EndpointObservationSender>,
) -> Result<()> {'''
forward_new=forward_sig.replace('async fn handle_forward_proxy(', 'async fn handle_forward_proxy_with_gate(').replace('    endpoint_observation_tx: Option<EndpointObservationSender>,\n) -> Result<()> {','    endpoint_observation_tx: Option<EndpointObservationSender>,\n    durable_egress_gate: Option<Arc<DurableEgressPermitGate>>,\n) -> Result<()> {')
s=rep(s,forward_sig,forward_new,'forward gated signature')
forward_wrapper=forward_sig.replace(') -> Result<()> {', ''') -> Result<()> {
    handle_forward_proxy_with_gate(
        method, target_uri, buf, used, client, supplied_identity, socket_addrs, opa_engine,
        identity_cache, entrypoint_pid, policy_local_ctx, agent_proposals, backend_host_gateway,
        trusted_host_gateway, provider_credentials, secret_resolver, dynamic_credentials,
        denial_tx, activity_tx, endpoint_observation_tx, None,
    ).await
}

''')
s=s.replace(forward_new, forward_wrapper+forward_new,1)

s=rep(s,'return Box::pin(handle_forward_proxy(\n','return Box::pin(handle_forward_proxy_with_gate(\n','mediated forward function')
s=rep(s,
'''            activity_tx.as_ref(),
            endpoint_observation_tx,
        ))''',
'''            activity_tx.as_ref(),
            endpoint_observation_tx,
            durable_egress_gate.clone(),
        ))''',
'mediated forward gate arg')

connect_anchor='''    let upstream_result = tokio::select! {
        result = dial_upstream(&upstream_proxy, &host_lc, &raw_host_lc, port, connector.addrs()) => Some(result),'''
connect_insert='''    if let Some(gate) = durable_egress_gate.as_ref() {
        let surface = if blackbox_transparent { EgressSurface::TransparentTcp } else { EgressSurface::Connect };
        let permit = gate.commit_before_effect(
            &connect_generation_guard,
            PermitInput {
                surface, host: &host_lc, port, matched_policy: policy_str,
                binary_path: &binary_str, binary_pid: decision.binary_pid,
            },
        ).await?;
        let _dispatch = gate.linearize_dispatch(&opa_engine, &connect_generation_guard, &permit)?;
    }

'''+connect_anchor
s=rep(s,connect_anchor,connect_insert,'connect permit hook')

forward_anchor='''    let dial_result = connector.connect().await;'''
forward_insert='''    if let Some(gate) = durable_egress_gate.as_ref() {
        let policy_name = match &decision.action {
            NetworkAction::Allow { matched_policy } => matched_policy.as_deref().unwrap_or("-"),
            NetworkAction::Deny { .. } => "-",
        };
        let permit = gate.commit_before_effect(
            &forward_generation_guard,
            PermitInput {
                surface: EgressSurface::ForwardHttp, host: &host_lc, port, matched_policy: policy_name,
                binary_path: &binary_str, binary_pid: decision.binary_pid,
            },
        ).await?;
        let _dispatch = gate.linearize_dispatch(&opa_engine, &forward_generation_guard, &permit)?;
    }
    let dial_result = connector.connect().await;'''
s=rep(s,forward_anchor,forward_insert,'forward permit hook')

s=rep(s,
'''        upstream_proxy_args: &upstream_proxy::UpstreamProxyArgs,
        engine_ready: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Self> {''',
'''        upstream_proxy_args: &upstream_proxy::UpstreamProxyArgs,
        engine_ready: tokio::sync::watch::Receiver<bool>,
        durable_egress_gate: Option<Arc<DurableEgressPermitGate>>,
    ) -> Result<Self> {''',
'transparent start gate signature')
s=rep(s,
'''                    let upstream_proxy = upstream_proxy.clone();
                    tokio::spawn(async move {''',
'''                    let upstream_proxy = upstream_proxy.clone();
                    let blackbox_gate = durable_egress_gate.clone();
                    tokio::spawn(async move {''',
'transparent clone gate')
s=rep(s,
'''                            activity_tx,
                            upstream_proxy,
                        )''',
'''                            activity_tx,
                            upstream_proxy,
                            blackbox_gate,
                        )''',
'transparent handler gate arg')
s=rep(s,
'''    activity_tx: Option<ActivitySender>,
    upstream_proxy: Arc<Option<UpstreamProxyConfig>>,
) -> Result<()> {''',
'''    activity_tx: Option<ActivitySender>,
    upstream_proxy: Arc<Option<UpstreamProxyConfig>>,
    durable_egress_gate: Option<Arc<DurableEgressPermitGate>>,
) -> Result<()> {''',
'transparent handler signature')
trans_anchor='''    let approved_real_ip_candidates = connector.addrs().to_vec();
    generation_guard.ensure_current()?;
    let mut upstream ='''
trans_insert='''    let approved_real_ip_candidates = connector.addrs().to_vec();
    generation_guard.ensure_current()?;
    if let Some(gate) = durable_egress_gate.as_ref() {
        let policy_name = match &decision.action {
            NetworkAction::Allow { matched_policy } => matched_policy.as_deref().unwrap_or("-"),
            NetworkAction::Deny { .. } => "-",
        };
        let binary = decision.binary.as_ref().map_or("-", |path| path.to_str().unwrap_or("-"));
        let permit = gate.commit_before_effect(
            &generation_guard,
            PermitInput {
                surface: EgressSurface::TransparentTcp, host: &host, port, matched_policy: policy_name,
                binary_path: binary, binary_pid: decision.binary_pid,
            },
        ).await?;
        let _dispatch = gate.linearize_dispatch(&opa_engine, &generation_guard, &permit)?;
    }
    let mut upstream ='''
s=rep(s,trans_anchor,trans_insert,'transparent permit hook')
write(p,s)

print('CP10 OpenShell patch applied')
