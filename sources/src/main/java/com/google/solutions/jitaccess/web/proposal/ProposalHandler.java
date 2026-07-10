//
// Copyright 2024 Google LLC
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//

package com.google.solutions.jitaccess.web.proposal;

import com.google.solutions.jitaccess.apis.clients.AccessException;
import com.google.solutions.jitaccess.auth.EndUserId;
import com.google.solutions.jitaccess.auth.IamPrincipalId;
import com.google.solutions.jitaccess.catalog.JitGroupContext;
import com.google.solutions.jitaccess.catalog.Proposal;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Tracks the state of proposals.
 */
public interface ProposalHandler {
  /**
   * Express the intent to join a group and solicit approval
   * from an authorized user.
   */
  default @NotNull ProposalHandler.ProposalToken propose(
    @NotNull JitGroupContext.JoinOperation joinOperation,
    @NotNull Function<String, URI> buildActionUri
  ) throws AccessException {
    return propose(joinOperation, buildActionUri, ProposeOptions.DEFAULT);
  }

  /**
   * Variant accepting per-request options:
   * <ul>
   *   <li>{@link ProposeOptions#reviewerFilter()} — narrow the set of
   *       qualified peers to a subset selected by the requester (the
   *       picker UX in the wavemm fork). Null = no filter.
   *   <li>{@link ProposeOptions#notifyReviewers()} — when false, the
   *       handler skips out-of-band notification (Slack DMs / email) but
   *       still generates and signs the JWT, returning the
   *       {@link ProposalToken} to the caller. Used by the "copy
   *       approval link" flow where the requester shares the link
   *       manually.
   * </ul>
   */
  @NotNull ProposalHandler.ProposalToken propose(
    @NotNull JitGroupContext.JoinOperation joinOperation,
    @NotNull Function<String, URI> buildActionUri,
    @NotNull ProposeOptions options
  ) throws AccessException;

  /**
   * Per-request options for {@link #propose}.
   *
   * @param reviewerFilter when non-null, narrows the recipients to
   *                       individuals selected by the requester
   * @param notifyReviewers when false, the proposal token is generated
   *                        but no Slack/email notification is delivered
   * @param reviewersAutoSelected wavemm fork (SECOP-1099): true when the
   *                              filter was picked by the auto-narrow on
   *                              the requester's behalf (empty picker
   *                              selection) rather than by the requester.
   *                              Handlers use this to tell the requester
   *                              who was notified and to teach the picker.
   */
  record ProposeOptions(
    @Nullable Set<EndUserId> reviewerFilter,
    boolean notifyReviewers,
    boolean reviewersAutoSelected
  ) {
    public ProposeOptions(
      @Nullable Set<EndUserId> reviewerFilter,
      boolean notifyReviewers
    ) {
      this(reviewerFilter, notifyReviewers, false);
    }

    public static final @NotNull ProposeOptions DEFAULT =
      new ProposeOptions(null, true, false);
  }

  /**
   * Accept a proposal.
   */
  @NotNull Proposal accept(
    @NotNull String proposalToken
  ) throws AccessException;

  /**
   * Wavemm fork (SECOP-1098): reorder an affinity-ranked list of
   * candidate reviewers to prefer those most likely to act quickly —
   * currently-active-on-Slack first, then in a working-hours timezone
   * close to the requester's — so an empty-selection auto-pick lands on
   * reviewers who can approve soon rather than ones who are asleep.
   *
   * <p>The default is a no-op passthrough: handlers without a presence
   * signal (mail, debug) keep the pure-affinity order. The Slack handler
   * overrides this. Availability is a *tiebreaker*, never a filter — an
   * offline teammate is deprioritised, not dropped, and any enrichment
   * failure falls back to the input order (fail-open).
   *
   * @param requester       the user whose request needs reviewers
   * @param affinityRanked  candidate reviewer emails, closest-first
   * @return the same emails, reordered availability-first
   */
  default @NotNull List<EndUserId> rankReviewersByAvailability(
    @NotNull EndUserId requester,
    @NotNull List<EndUserId> affinityRanked
  ) {
    return affinityRanked;
  }

  /**
   * Wavemm fork (SECOP-1093): read-only check that a proposal token
   * hasn't been used to approve — used by the GET proposal-view path to
   * render "this link has already been used" instead of an approval
   * page whose submit would then fail. NOT the enforcement gate; that is
   * {@link #claimForApproval} (a read here would be a TOCTOU).
   *
   * <p>Default no-op: handlers without a consumption store (mail, debug)
   * keep upstream replayable semantics.
   *
   * @throws AccessException when the proposal was already consumed
   */
  default void verifyNotConsumed(@NotNull Proposal proposal)
    throws AccessException {
  }

  /**
   * Wavemm fork (SECOP-1100): atomically claim a proposal token for
   * approval, so exactly one approval executes even under concurrent
   * clicks on the same link. Called immediately BEFORE the approval
   * executes; on {@code ALREADY_EXISTS} it throws, so the second
   * concurrent (or any later) approver is rejected rather than
   * re-granting. Replaces the previous post-execute {@code markConsumed}
   * upsert, whose check-then-act window let concurrent approvers all
   * pass.
   *
   * <p>Default no-op (mail/debug stay replayable). The Slack handler
   * fails open on infrastructure errors — availability over
   * replay-protection, matching SECOP-1093 — but treats an explicit
   * already-claimed result as a hard reject.
   *
   * @throws AccessException when the token is already claimed/consumed
   */
  default void claimForApproval(@NotNull Proposal proposal)
    throws AccessException {
  }

  /**
   * Wavemm fork (SECOP-1100): release a claim taken by
   * {@link #claimForApproval} when the approval did not complete (e.g.
   * the execute failed before granting), so a legitimate retry can
   * approve. Best-effort; a failed release leaves the token burned,
   * which is the fail-safe direction.
   */
  default void releaseClaim(@NotNull Proposal proposal) {
  }

  /**
   * Token that encodes all information about a proposal in a tamper-proof
   * way, suitable for exchanging in URLs and/or email messages.
   */
  record ProposalToken(
    @NotNull String value,
    @NotNull Set<IamPrincipalId> audience,
    @NotNull Instant expiryTime
  ) {
    @Override
    public String toString() {
      return this.value;
    }
  }
}
