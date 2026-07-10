//
// Copyright 2026 Wave Mobile Money / wavemm fork
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//

package com.google.solutions.jitaccess.web.proposal;

import com.google.common.base.Preconditions;
import com.google.solutions.jitaccess.apis.Logger;
import com.google.solutions.jitaccess.common.CompletableFutures;
import com.slack.api.Slack;
import com.slack.api.methods.MethodsClient;
import com.slack.api.methods.SlackApiException;
import com.slack.api.methods.response.chat.ChatPostMessageResponse;
import com.slack.api.methods.response.chat.ChatUpdateResponse;
import com.slack.api.methods.response.conversations.ConversationsOpenResponse;
import com.slack.api.methods.response.users.UsersGetPresenceResponse;
import com.slack.api.methods.response.users.UsersInfoResponse;
import com.slack.api.methods.response.users.UsersLookupByEmailResponse;
import com.slack.api.model.block.LayoutBlock;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Thin wrapper around the Slack Web API.
 *
 * <p>All public methods are async. Failures bubble out as failed futures —
 * the caller (SlackProposalHandler) decides whether to log+swallow or
 * propagate. JIT request threads must never block on Slack.
 */
public class SlackClient {
  private final @NotNull MethodsClient methods;
  private final @NotNull Executor executor;
  private final @NotNull Logger logger;

  public SlackClient(
    @NotNull String botToken,
    @NotNull Executor executor,
    @NotNull Logger logger
  ) {
    Preconditions.checkArgument(!botToken.isBlank(), "botToken must not be blank");
    this.methods = Slack.getInstance().methods(botToken);
    this.executor = executor;
    this.logger = logger;
  }

  /**
   * Look up a Slack user by email. Returns null when the email is not
   * registered in the workspace (e.g. external collaborators) — that's
   * a normal outcome, not an error.
   */
  public @NotNull CompletableFuture<@Nullable String> lookupUserByEmail(
    @NotNull String email
  ) {
    return CompletableFutures.supplyAsync(() -> {
      try {
        UsersLookupByEmailResponse response = this.methods.usersLookupByEmail(req -> req.email(email));
        if (!response.isOk()) {
          if ("users_not_found".equals(response.getError())) {
            return null;
          }
          throw new IOException("users.lookupByEmail failed: " + response.getError());
        }
        return response.getUser() != null ? response.getUser().getId() : null;
      }
      catch (SlackApiException e) {
        throw new IOException("Slack API error in users.lookupByEmail for " + email, e);
      }
    }, this.executor);
  }

  /**
   * Open a DM channel with the user and post a Block Kit message. Returns
   * (channelId, ts) for later {@link #updateMessage} calls.
   */
  public @NotNull CompletableFuture<PostedMessage> postDirectMessage(
    @NotNull String slackUserId,
    @NotNull List<LayoutBlock> blocks,
    @NotNull String fallbackText
  ) {
    return CompletableFutures.supplyAsync(() -> {
      try {
        ConversationsOpenResponse open = this.methods.conversationsOpen(
          req -> req.users(List.of(slackUserId)));
        if (!open.isOk() || open.getChannel() == null) {
          throw new IOException(
            "conversations.open failed for user " + slackUserId + ": " + open.getError());
        }
        var channelId = open.getChannel().getId();

        ChatPostMessageResponse post = this.methods.chatPostMessage(req -> req
          .channel(channelId)
          .blocks(blocks)
          .text(fallbackText));
        if (!post.isOk()) {
          throw new IOException("chat.postMessage failed: " + post.getError());
        }
        return new PostedMessage(channelId, post.getTs());
      }
      catch (SlackApiException e) {
        throw new IOException("Slack API error posting DM to " + slackUserId, e);
      }
    }, this.executor);
  }

  /**
   * Replace the blocks of an already-posted message. Used to mark sibling
   * reviewer DMs as "approved by X" without removing the original message.
   * <p>
   * Errors are logged at WARN and absorbed — losing a sibling update is not
   * worth failing the approval flow over.
   */
  public @NotNull CompletableFuture<Void> updateMessage(
    @NotNull String channelId,
    @NotNull String messageTs,
    @NotNull List<LayoutBlock> blocks,
    @NotNull String fallbackText
  ) {
    return CompletableFutures.supplyAsync(() -> {
      try {
        ChatUpdateResponse response = this.methods.chatUpdate(req -> req
          .channel(channelId)
          .ts(messageTs)
          .blocks(blocks)
          .text(fallbackText));
        if (!response.isOk()) {
          this.logger.warn(
            "slack.updateMessage.failed",
            "chat.update failed for %s/%s: %s",
            channelId, messageTs, response.getError());
        }
        return null;
      }
      catch (SlackApiException e) {
        throw new IOException(
          "Slack API error updating message " + channelId + "/" + messageTs, e);
      }
    }, this.executor);
  }

  /**
   * Whether a user is currently active on Slack (SECOP-1098). "active"
   * vs "away" is a coarse signal (desktop idle reads as away), so
   * callers use it to prioritise, never to exclude. Returns false when
   * presence can't be determined — a conservative default that just
   * means "don't prioritise", not "unavailable".
   */
  public @NotNull CompletableFuture<Boolean> isActive(
    @NotNull String slackUserId
  ) {
    return CompletableFutures.supplyAsync(() -> {
      try {
        UsersGetPresenceResponse response =
          this.methods.usersGetPresence(req -> req.user(slackUserId));
        if (!response.isOk()) {
          // SECOP-1104: surface it. A persistent error (e.g.
          // missing_scope for users:read — a scope this feature newly
          // requires) would otherwise silently degrade every candidate
          // to "not active", making the availability ranking an inert
          // no-op with no signal.
          this.logger.warn(
            "slack.getPresence.failed",
            "users.getPresence for %s failed: %s (treating as not active)",
            slackUserId, response.getError());
          return false;
        }
        return "active".equals(response.getPresence());
      }
      catch (SlackApiException e) {
        throw new IOException("Slack API error in users.getPresence for " + slackUserId, e);
      }
    }, this.executor);
  }

  /**
   * The user's timezone offset from UTC in seconds (SECOP-1098), or null
   * when unknown. Used to prefer reviewers in working hours close to the
   * requester's.
   */
  public @NotNull CompletableFuture<@Nullable Integer> timezoneOffsetSeconds(
    @NotNull String slackUserId
  ) {
    return CompletableFutures.supplyAsync(() -> {
      try {
        UsersInfoResponse response =
          this.methods.usersInfo(req -> req.user(slackUserId));
        if (!response.isOk()) {
          this.logger.warn(
            "slack.usersInfo.failed",
            "users.info for %s failed: %s (timezone unknown)",
            slackUserId, response.getError());
          return null;
        }
        if (response.getUser() == null) {
          return null;
        }
        return response.getUser().getTzOffset();
      }
      catch (SlackApiException e) {
        throw new IOException("Slack API error in users.info for " + slackUserId, e);
      }
    }, this.executor);
  }

  /**
   * A successfully posted Slack message, identified by (channel, timestamp).
   */
  public record PostedMessage(
    @NotNull String channelId,
    @NotNull String messageTs
  ) {}
}
