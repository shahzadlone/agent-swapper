//! Local session references are intent metadata, not runtime existence receipts.
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{Store, journal};
use crate::{Error, GentsBinding, Harness, ProfileId, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GentsSession {
    id: Uuid,
    binding: GentsBinding,
    resumed_from: Option<Uuid>,
}

impl GentsSession {
    pub(crate) fn new(id: Uuid, binding: GentsBinding, resumed_from: Option<Uuid>) -> Self {
        Self {
            id,
            binding,
            resumed_from,
        }
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn binding(&self) -> &GentsBinding {
        &self.binding
    }
    pub fn resumed_from(&self) -> Option<Uuid> {
        self.resumed_from
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeCandidate {
    pub run_id: Uuid,
    pub session: GentsSession,
}

impl Store {
    /// Select the latest attempt, never silently fall back past a failed,
    /// unresolved, legacy or rebound run. Caller must revalidate before spawn.
    pub fn latest_gents_session(&self, profile: ProfileId) -> Result<ResumeCandidate> {
        let snapshot = self.db.unchecked_transaction()?;
        if !journal::verify_snapshot(&snapshot)?.consistent {
            return Err(Error::ProjectionMismatch);
        }
        let candidate = latest(&snapshot, profile)?;
        snapshot.commit()?;
        Ok(candidate)
    }
}

pub(super) fn latest(db: &Connection, profile: ProfileId) -> Result<ResumeCandidate> {
    let (harness, binding): (String, Option<String>) = db
        .query_row(
            "SELECT harness,gents FROM main.profiles WHERE id=?1 AND retired=0",
            [profile.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or(Error::NotFound)?;
    if harness.parse::<Harness>()? != Harness::Gents {
        return Err(Error::UnsupportedSession);
    }
    let binding: GentsBinding = serde_json::from_str(&binding.ok_or(Error::CorruptRegistry)?)
        .map_err(|_| Error::CorruptRegistry)?;
    let mut query = db.prepare("SELECT r.id,r.gents_session,r.observed_pid,r.exit_code,r.outcome FROM main.runs r JOIN main.event_log e ON json_extract(e.payload,'$.type')='run_planned' AND json_extract(e.payload,'$.id')=r.id WHERE r.profile=?1 ORDER BY e.sequence DESC LIMIT 1")?;
    let mut rows = query.query([profile.to_string()])?;
    let row = rows.next()?.ok_or(Error::NoRecordedSession)?;
    let json: Option<String> = row.get(1)?;
    let session: GentsSession = serde_json::from_str(&json.ok_or(Error::NoRecordedSession)?)
        .map_err(|_| Error::CorruptRegistry)?;
    if session.binding != binding {
        return Err(Error::SessionBindingChanged);
    }
    let pid: Option<u32> = row.get(2)?;
    let exit: Option<i32> = row.get(3)?;
    let outcome: Option<String> = row.get(4)?;
    if pid.is_none() || exit != Some(0) || outcome.as_deref() != Some("external_client_exited") {
        return Err(Error::SessionNotResumable);
    }
    let id: String = row.get(0)?;
    Ok(ResumeCandidate {
        run_id: Uuid::parse_str(&id).map_err(|_| Error::CorruptRegistry)?,
        session,
    })
}

/// Executed inside the event transaction and during replay at the same point in
/// history. The run being appended is not in the projection yet.
pub(super) fn validate_intent(
    db: &Connection,
    profile: ProfileId,
    session: &GentsSession,
) -> Result<()> {
    let binding: Option<String> = db
        .query_row(
            "SELECT gents FROM main.profiles WHERE id=?1 AND harness='gents' AND retired=0",
            [profile.to_string()],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let binding: GentsBinding = serde_json::from_str(&binding.ok_or(Error::EngineMismatch)?)
        .map_err(|_| Error::CorruptRegistry)?;
    if session.binding != binding {
        return Err(Error::SessionBindingChanged);
    }
    if let Some(source) = session.resumed_from {
        let candidate = latest(db, profile)?;
        if candidate.run_id != source || candidate.session.id != session.id {
            return Err(Error::StaleSession);
        }
    }
    // Session IDs are gents metadata, not an ownership or remote-existence proof.
    Ok(())
}

#[cfg(test)]
mod tests;
