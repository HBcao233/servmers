use std::sync::Arc;

use dashmap::DashMap;

/// MTProto session IDs are scoped to an authorization key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionKey {
    pub auth_key_id: [u8; 8],
    pub session_id: i64,
}

#[derive(Debug)]
pub struct Session {
    key: SessionKey,
}

impl Session {
    pub fn new(key: SessionKey) -> Self {
        Self { key }
    }

    pub fn key(&self) -> SessionKey {
        self.key
    }
}

/// Shared sessions survive individual TCP connections. Call `remove` when a
/// session expires or is explicitly destroyed.
#[derive(Default)]
pub struct Registry {
    sessions: DashMap<SessionKey, Arc<Session>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&self, key: SessionKey) -> Arc<Session> {
        Arc::clone(
            self.sessions
                .entry(key)
                .or_insert_with(|| Arc::new(Session::new(key)))
                .value(),
        )
    }

    pub fn get(&self, key: &SessionKey) -> Option<Arc<Session>> {
        self.sessions
            .get(key)
            .map(|entry| Arc::clone(entry.value()))
    }

    pub fn remove(&self, key: &SessionKey) -> Option<Arc<Session>> {
        self.sessions.remove(key).map(|(_, session)| session)
    }
}
