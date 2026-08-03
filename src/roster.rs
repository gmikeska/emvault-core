//! Pure roster arithmetic for a federation migration.
//!
//! A migration carries an arbitrary roster delta: any number of adds and
//! removes, applied to the current version's members to produce the next
//! version's roster. This module computes that delta and the per-member
//! actions a consumer persists, plus threshold validation — all pure (no DB,
//! no framework), so it is exhaustively unit-tested.
//!
//! Members are identified by [`Uuid`]; per the extraction design these are the
//! consumer's user/member ids. Threshold values are `u32`/[`NonZeroU32`] — the
//! domain layer never carries storage-shaped `i32` (consumers convert at their
//! own edge).

use std::collections::HashSet;
use std::num::NonZeroU32;

use uuid::Uuid;

/// Per-member action recorded for a migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterAction {
    /// Member of both the base and next version.
    Keep,
    /// Joining the next version.
    Add,
    /// Leaving in the next version.
    Remove,
}

impl RosterAction {
    /// The persisted action string for this action (`keep` / `add` / `remove`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RosterAction::Keep => "keep",
            RosterAction::Add => "add",
            RosterAction::Remove => "remove",
        }
    }
}

/// The computed result of applying a roster delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterPlan {
    /// The next version's members (kept ∪ added), in deterministic order
    /// (kept-in-base-order, then added-in-input-order). This is the roster the
    /// successor federation is built from.
    pub next_members: Vec<Uuid>,
    /// Every affected member with its action — the rows a consumer persists
    /// (`keep` for retained, `add` for joiners, `remove` for leavers).
    pub changes: Vec<(Uuid, RosterAction)>,
}

/// Errors from computing a roster delta or validating a threshold.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RosterError {
    /// A `remove` targets a user who isn't a current member.
    #[error("user {0} is not a current member and cannot be removed")]
    RemoveNotMember(Uuid),
    /// An `add` targets a user who is already a member.
    #[error("user {0} is already a member and cannot be added")]
    AddAlreadyMember(Uuid),
    /// A user appears in both the add and remove sets.
    #[error("user {0} cannot be both added and removed in one migration")]
    AddAndRemove(Uuid),
    /// The delta would leave the next version with no members.
    #[error("the next federation would have no members")]
    EmptyResult,
    /// Threshold out of `1..=n`.
    #[error("threshold {m} must be between 1 and {n}")]
    BadThreshold {
        /// Requested threshold.
        m: u32,
        /// Next-version member count.
        n: usize,
    },
}

/// Apply an arbitrary add/remove delta to `current` members, returning the next
/// roster plus the per-member action list.
///
/// `current`, `add`, and `remove` are de-duplicated internally. The result is
/// deterministic regardless of input ordering of duplicates.
///
/// # Errors
///
/// - [`RosterError::AddAndRemove`] if a user is in both `add` and `remove`.
/// - [`RosterError::RemoveNotMember`] if a `remove` isn't a current member.
/// - [`RosterError::AddAlreadyMember`] if an `add` is already a member.
/// - [`RosterError::EmptyResult`] if no members would remain.
///
/// # Example
///
/// ```
/// use emvault_core::roster::{compute_roster_plan, RosterAction};
/// use uuid::Uuid;
///
/// let alice = Uuid::from_u128(1);
/// let bob = Uuid::from_u128(2);
/// let carol = Uuid::from_u128(3);
///
/// // Start from {alice, bob}; add carol and remove bob.
/// let plan = compute_roster_plan(&[alice, bob], &[carol], &[bob])?;
///
/// assert_eq!(plan.next_members, vec![alice, carol]);
/// assert_eq!(
///     plan.changes,
///     vec![
///         (alice, RosterAction::Keep),
///         (bob, RosterAction::Remove),
///         (carol, RosterAction::Add),
///     ],
/// );
/// # Ok::<(), emvault_core::roster::RosterError>(())
/// ```
pub fn compute_roster_plan(
    current: &[Uuid],
    add: &[Uuid],
    remove: &[Uuid],
) -> Result<RosterPlan, RosterError> {
    let current_set: HashSet<Uuid> = current.iter().copied().collect();
    let add_set: HashSet<Uuid> = add.iter().copied().collect();
    let remove_set: HashSet<Uuid> = remove.iter().copied().collect();

    if let Some(&u) = add_set.intersection(&remove_set).next() {
        return Err(RosterError::AddAndRemove(u));
    }
    for &u in &remove_set {
        if !current_set.contains(&u) {
            return Err(RosterError::RemoveNotMember(u));
        }
    }
    for &u in &add_set {
        if current_set.contains(&u) {
            return Err(RosterError::AddAlreadyMember(u));
        }
    }

    let mut next_members = Vec::new();
    let mut changes = Vec::new();
    let mut seen: HashSet<Uuid> = HashSet::new();

    // Kept / removed, in base order.
    for &u in current {
        if !seen.insert(u) {
            continue;
        }
        if remove_set.contains(&u) {
            changes.push((u, RosterAction::Remove));
        } else {
            next_members.push(u);
            changes.push((u, RosterAction::Keep));
        }
    }
    // Added, in input order.
    for &u in add {
        if !seen.insert(u) {
            continue;
        }
        next_members.push(u);
        changes.push((u, RosterAction::Add));
    }

    if next_members.is_empty() {
        return Err(RosterError::EmptyResult);
    }
    Ok(RosterPlan {
        next_members,
        changes,
    })
}

/// Validate that threshold `m` is in `1..=n` for an `n`-member next version,
/// returning it as a [`NonZeroU32`] (the `≥ 1` invariant encoded in the type).
///
/// # Errors
///
/// [`RosterError::BadThreshold`] if `m == 0`, `m > n`, or `n` overflows `u32`.
pub fn validate_threshold(m: u32, n: usize) -> Result<NonZeroU32, RosterError> {
    let n_u32 = u32::try_from(n).map_err(|_| RosterError::BadThreshold { m, n })?;
    if m == 0 || m > n_u32 {
        return Err(RosterError::BadThreshold { m, n });
    }
    NonZeroU32::new(m).ok_or(RosterError::BadThreshold { m, n })
}

/// A historic version's relay-signing requirement: the members who can sign for
/// it and its threshold.
pub struct HistoricVersion {
    /// The version's member user ids (immutable — relay needs `threshold` of these).
    pub members: Vec<Uuid>,
    /// The version's signing threshold.
    pub threshold: u32,
}

/// Identify historic versions whose **relay** would be at risk after a roster
/// change: fewer than `threshold` of their members remain in `next_current`
/// (the active roster after the migration). Such a version's late-inflow relay
/// would depend on people no longer in the active federation — worth warning the
/// operator. Returns indices into `historic`.
///
/// Advisory only: a removed member is still a member of the historic version and
/// *can* sign its relay if they cooperate; this flags the versions where that
/// cooperation becomes load-bearing.
#[must_use]
pub fn historic_versions_at_risk(
    historic: &[HistoricVersion],
    next_current: &[Uuid],
) -> Vec<usize> {
    let active: HashSet<Uuid> = next_current.iter().copied().collect();
    historic
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            let overlap = v.members.iter().filter(|m| active.contains(m)).count();
            let need = usize::try_from(v.threshold).unwrap_or(usize::MAX);
            (overlap < need).then_some(i)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    #[test]
    fn remove_one_add_one_in_a_single_migration() {
        // 2-of-3 {s1,s2,s3} → remove s2, add s4 → {s1,s3,s4}.
        let v = ids(4);
        let (s1, s2, s3, s4) = (v[0], v[1], v[2], v[3]);
        let plan = compute_roster_plan(&[s1, s2, s3], &[s4], &[s2]).unwrap();

        assert_eq!(plan.next_members, vec![s1, s3, s4]);
        assert_eq!(
            plan.changes,
            vec![
                (s1, RosterAction::Keep),
                (s2, RosterAction::Remove),
                (s3, RosterAction::Keep),
                (s4, RosterAction::Add),
            ]
        );
    }

    #[test]
    fn arbitrary_number_of_changes() {
        let v = ids(6);
        // {a,b,c,d} → remove b,d ; add e,f → {a,c,e,f}.
        let plan =
            compute_roster_plan(&[v[0], v[1], v[2], v[3]], &[v[4], v[5]], &[v[1], v[3]]).unwrap();
        assert_eq!(plan.next_members, vec![v[0], v[2], v[4], v[5]]);
        let removes = plan
            .changes
            .iter()
            .filter(|(_, a)| *a == RosterAction::Remove)
            .count();
        assert_eq!(removes, 2);
    }

    #[test]
    fn rejects_remove_of_non_member() {
        let v = ids(3);
        let err = compute_roster_plan(&[v[0], v[1]], &[], &[v[2]]).unwrap_err();
        assert_eq!(err, RosterError::RemoveNotMember(v[2]));
    }

    #[test]
    fn rejects_add_of_existing_member() {
        let v = ids(2);
        let err = compute_roster_plan(&[v[0], v[1]], &[v[0]], &[]).unwrap_err();
        assert_eq!(err, RosterError::AddAlreadyMember(v[0]));
    }

    #[test]
    fn rejects_add_and_remove_same_user() {
        let v = ids(2);
        let err = compute_roster_plan(&[v[0], v[1]], &[v[1]], &[v[1]]).unwrap_err();
        // v[1] is an existing member, so it is caught as add-and-remove first.
        assert_eq!(err, RosterError::AddAndRemove(v[1]));
    }

    #[test]
    fn rejects_emptying_the_federation() {
        let v = ids(2);
        let err = compute_roster_plan(&[v[0], v[1]], &[], &[v[0], v[1]]).unwrap_err();
        assert_eq!(err, RosterError::EmptyResult);
    }

    #[test]
    fn threshold_bounds() {
        assert_eq!(validate_threshold(2, 3).unwrap().get(), 2);
        assert_eq!(validate_threshold(1, 1).unwrap().get(), 1);
        assert_eq!(validate_threshold(3, 3).unwrap().get(), 3);
        assert!(validate_threshold(0, 3).is_err());
        assert!(validate_threshold(4, 3).is_err());
    }

    #[test]
    fn relay_liveness_flags_stranded_historic_versions() {
        let m = ids(5);
        // Historic v0 = 2-of-3 {m0, m1, m2}.
        let historic = vec![HistoricVersion {
            members: vec![m[0], m[1], m[2]],
            threshold: 2,
        }];

        // Next current keeps only m0 from v0 → overlap 1 < 2 → at risk.
        assert_eq!(
            historic_versions_at_risk(&historic, &[m[0], m[3], m[4]]),
            vec![0]
        );
        // Next current keeps m0 + m1 → overlap 2 ≥ 2 → safe.
        assert!(historic_versions_at_risk(&historic, &[m[0], m[1], m[3]]).is_empty());
    }
}
