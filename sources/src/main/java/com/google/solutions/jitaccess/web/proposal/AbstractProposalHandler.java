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

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.webtoken.JsonWebToken;
import com.google.auth.oauth2.TokenVerifier;
import com.google.common.base.Preconditions;
import com.google.solutions.jitaccess.apis.clients.AccessDeniedException;
import com.google.solutions.jitaccess.apis.clients.AccessException;
import com.google.solutions.jitaccess.auth.EndUserId;
import com.google.solutions.jitaccess.auth.IamPrincipalId;
import com.google.solutions.jitaccess.auth.JitGroupId;
import com.google.solutions.jitaccess.auth.PrincipalId;
import com.google.solutions.jitaccess.catalog.JitGroupContext;
import com.google.solutions.jitaccess.catalog.Proposal;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public abstract class AbstractProposalHandler implements ProposalHandler {
  private final @NotNull TokenSigner tokenSigner;
  private final @NotNull Random jwtIdGenerator;
  private final @NotNull Options options;

  protected AbstractProposalHandler(
    @NotNull TokenSigner tokenSigner,
    @NotNull Random jwtIdGenerator,
    @NotNull Options options
  ) {
    this.tokenSigner = tokenSigner;
    this.jwtIdGenerator = jwtIdGenerator;
    this.options = options;
  }

  /**
   * Notify relevant users about a proposal.
   */
  abstract void onOperationProposed(
    @NotNull JitGroupContext.JoinOperation operation,
    @NotNull Proposal proposal,
    @NotNull ProposalHandler.ProposalToken token,
    @NotNull URI actionUri
    ) throws AccessException, IOException;

  /**
   * Options-aware variant (wavemm fork, SECOP-1099). The base
   * implementation ignores the options so existing handlers (mail,
   * debug) stay unchanged; handlers that care (Slack) override this
   * one — e.g. to tell the requester who was auto-notified when the
   * reviewer set was picked on their behalf.
   */
  void onOperationProposed(
    @NotNull JitGroupContext.JoinOperation operation,
    @NotNull Proposal proposal,
    @NotNull ProposalHandler.ProposalToken token,
    @NotNull URI actionUri,
    @NotNull ProposalHandler.ProposeOptions options
  ) throws AccessException, IOException {
    onOperationProposed(operation, proposal, token, actionUri);
  }

  /**
   * Notify relevant users about the completion of a proposal.
   */
  abstract void onProposalApproved(
    @NotNull JitGroupContext.ApprovalOperation operation,
    @NotNull Proposal proposal
  ) throws AccessException, IOException;

  //---------------------------------------------------------------------------
  // ProposalHandler.
  //---------------------------------------------------------------------------

  @Override
  public @NotNull ProposalHandler.ProposalToken propose(
    @NotNull JitGroupContext.JoinOperation joinOperation,
    @NotNull Function<String, URI> buildActionUri,
    @NotNull ProposeOptions options
  ) throws AccessException {

    var expiry = Instant.now().plus(this.options.tokenExpiry);
    var proposal = joinOperation.propose(
      expiry,
      options.reviewerFilter());

    Preconditions.checkArgument(
      !proposal.recipients().isEmpty(),
      "Recipients must not be empty");
    Preconditions.checkArgument(
      !proposal.recipients().contains(proposal.user()),
      "Recipients must not contain the requesting user");

    //
    // SECOP-1101: reject duplicate in-flight requests BEFORE minting a
    // token. Atomically reserve a pending marker; if one already exists
    // (and hasn't expired), this is a re-submit of a request whose
    // reviewers were already notified — throw rather than mint a second
    // approvable token and fan out a second DM batch. Copy-link
    // (notifyReviewers=false) is exempt: it sends no DMs and each call
    // legitimately wants its own link. The reservation is released below
    // if minting/notification fails, so a genuine retry isn't locked out.
    //
    boolean reserved = false;
    if (options.notifyReviewers()) {
      if (!reserveProposal(proposal, options.reviewersAutoSelected(), expiry)) {
        throw new AccessDeniedException(
          "You already have a pending approval request for this group. "
            + "Wait for a reviewer to act on it, or for it to expire, "
            + "before submitting another.");
      }
      reserved = true;
    }

    //
    // Encode all inputs into a token and sign it.
    //
    var inputs = new GenericJson();
    proposal.input()
      .entrySet()
      .forEach(p -> inputs.set(p.getKey(), p.getValue()));

    var jwtId = new byte[6];
    this.jwtIdGenerator.nextBytes(jwtId);

    var payload = new JsonWebToken.Payload()
      .setJwtId(Base64.getEncoder().encodeToString(jwtId))
      .set(Claims.RECIPIENT, proposal.recipients()
        .stream()
        .sorted()
        .map(PrincipalId::toString)
        .toArray())
      .set(Claims.GROUP_ID, joinOperation.group().toString())
      .set(Claims.USER_ID, proposal.user().toString())
      .set(Claims.INPUT, inputs);

    //
    // Wavemm fork: encode the notify-reviewers flag in the JWT only when
    // the requester opted out. Default-on means we don't pollute every
    // existing token with a redundant claim, and the accept() path
    // treats absence as the upstream "true" default.
    //
    if (!options.notifyReviewers()) {
      payload.set(Claims.NOTIFY, Boolean.FALSE);
    }

    try {
      var signedToken = this.tokenSigner.sign(
        payload,
        proposal.expiry());
      var proposalToken = new ProposalToken(
        signedToken.token(),
        proposal.recipients(),
        signedToken.expiryTime());

      //
      // Skip notification delivery when the caller opted out — the JWT
      // is still generated, signed, and returned, so the requester can
      // copy/share the action URL manually (e.g. send to a specific
      // reviewer in Slack DM themselves).
      //
      if (options.notifyReviewers()) {
        onOperationProposed(
          joinOperation,
          proposal,
          proposalToken,
          buildActionUri.apply(proposalToken.value()),
          options);
      }

      return proposalToken;
    }
    catch (AccessException | IOException | RuntimeException e) {
      // SECOP-1101: minting/notification failed after we reserved —
      // release the pending marker so a legitimate retry isn't blocked
      // for the token lifetime.
      if (reserved) {
        releaseProposalReservation(proposal, options.reviewersAutoSelected());
      }
      if (e instanceof RuntimeException runtime) {
        throw runtime;
      }
      throw new AccessDeniedException(
        "Creating a proposal failed", e);
    }
  }

  /**
   * Wavemm fork (SECOP-1101): atomically reserve a pending-request
   * marker before a token is minted, returning {@code false} if a live
   * (non-expired) reservation already exists — i.e. this is a duplicate
   * submit. Default no-op returning {@code true} (mail/debug don't
   * dedupe). The key an implementation uses MUST be stable across the
   * retries a requester makes: keyed on (beneficiary, group) when the
   * reviewers were auto-selected (the picked set can shift between
   * submits), and on (beneficiary, group, recipients) when the
   * requester picked reviewers explicitly.
   */
  boolean reserveProposal(
    @NotNull Proposal proposal,
    boolean reviewersAutoSelected,
    @NotNull Instant expiry
  ) throws AccessException {
    return true;
  }

  /**
   * Wavemm fork (SECOP-1101): release a reservation taken by
   * {@link #reserveProposal} when the propose failed after reserving.
   * Best-effort; default no-op.
   */
  void releaseProposalReservation(
    @NotNull Proposal proposal,
    boolean reviewersAutoSelected
  ) {
  }

  @SuppressWarnings("unchecked")
  @Override
  public @NotNull Proposal accept(
    @NotNull String proposalToken
  ) throws AccessException {

    JsonWebToken.Payload payload;
    try {
      payload = this.tokenSigner.verify(proposalToken);
    }
    catch (TokenVerifier.VerificationException e) {
      throw new AccessDeniedException("The proposal token is invalid", e);
    }

    var user = EndUserId
      .parse((String)payload.get(Claims.USER_ID))
      .orElseThrow(() -> new IllegalArgumentException("Invalid user ID"));

    var group = JitGroupId
      .parse((String)payload.get(Claims.GROUP_ID))
      .orElseThrow(() ->
        new AccessDeniedException("The group does not exist or access is denied"));

    var recipients = ((List<String>)payload.get(Claims.RECIPIENT))
      .stream()
      .flatMap(p -> IamPrincipalId.parse(p).stream())
      .collect(Collectors.toSet());

    var input = ((Map<String, Object>)payload.get(Claims.INPUT))
      .entrySet()
      .stream()
      .collect(Collectors.toMap(e -> e.getKey(), e-> (String)e.getValue()));

    // Wavemm fork: read the opt-out claim. Absent or true → default
    // upstream behaviour; explicit false → requester chose to share
    // the link manually, no DMs were sent at propose-time.
    var notifyClaim = payload.get(Claims.NOTIFY);
    final boolean notifyReviewers = !(notifyClaim instanceof Boolean && !((Boolean) notifyClaim));

    return new Proposal() {
      @Override
      public @NotNull EndUserId user() {
        return user;
      }

      @Override
      public String id() {
        // The jti minted at propose-time: 6 crypto-random bytes, base64.
        // Anchors single-use consumption tracking (SECOP-1093).
        return payload.getJwtId();
      }

      @Override
      public @NotNull JitGroupId group() {
        return group;
      }

      @Override
      public @NotNull Set<IamPrincipalId> recipients() {
        return recipients;
      }

      @Override
      public @NotNull Instant expiry() {
        return Instant.ofEpochSecond(payload.getExpirationTimeSeconds());
      }

      @Override
      public @NotNull Map<String, String> input() {
        return input;
      }

      @Override
      public boolean notifyReviewers() {
        return notifyReviewers;
      }

      @Override
      public void onCompleted(
        @NotNull JitGroupContext.ApprovalOperation op
      ) throws AccessException, IOException {
        onProposalApproved(op, this);
      }
    };
  }

  static class Claims {
    static final String RECIPIENT = "rcp";
    static final String GROUP_ID = "grp";
    static final String USER_ID = "usr";
    static final String INPUT = "inp";
    /** Wavemm fork: only present when the requester opted out of
     *  automated reviewer notification. Absence means the upstream
     *  default — notify reviewers — applies. */
    static final String NOTIFY = "ntf";
  }

  public record Options(
    @NotNull Duration tokenExpiry
  ) {
    public Options {
      Preconditions.checkArgument(
        !tokenExpiry.isNegative() && !tokenExpiry.isZero(),
        "Expiry must be positive");
    }
  }
}
