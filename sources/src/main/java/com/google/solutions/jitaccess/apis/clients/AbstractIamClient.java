//
// Copyright 2021 Google LLC
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

package com.google.solutions.jitaccess.apis.clients;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.googleapis.services.json.AbstractGoogleJsonClient;
import com.google.api.client.googleapis.services.json.AbstractGoogleJsonClientRequest;
import com.google.api.services.cloudresourcemanager.v3.model.GetIamPolicyRequest;
import com.google.api.services.cloudresourcemanager.v3.model.GetPolicyOptions;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.api.services.cloudresourcemanager.v3.model.SetIamPolicyRequest;
import com.google.common.base.Preconditions;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.function.Consumer;

/**
 * Base class for APIs that support getIamPolicy and setIamPolicy methods.
 */
public abstract class AbstractIamClient {
  private static final int MAX_SET_IAM_POLICY_ATTEMPTS = 4;

  /**
   * Bounded retries for the "member not in permitted organization"
   * propagation race (SECOP-1096). Separate budget from the
   * concurrency-control attempts so a slow propagation can't starve
   * 412 handling. 3 attempts at 2s/4s/8s ≈ 14s covers the lag observed
   * in production (a newly-created JIT group took ~15–26s to become
   * resolvable by the org-policy member-domain checker).
   */
  private static final int MAX_MEMBER_DOMAIN_PROPAGATION_ATTEMPTS = 3;

  private static boolean isRoleNotGrantableErrorMessage(@Nullable String message)
  {
    return message != null &&
      (message.contains("not supported") || message.contains("does not exist"));
  }

  /**
   * True for the transient 400 raised when a binding names a principal
   * the {@code iam.allowedPolicyMemberDomains} org-policy checker can't
   * yet resolve — the dominant cause being a Google group created
   * moments earlier (JIT lazily provisions the group on first join,
   * then immediately tries to bind it org-wide). Membership propagation
   * clears within tens of seconds, so this is retryable; a genuinely
   * disallowed member simply exhausts the bounded retries and surfaces
   * as before. Deliberately narrow (both the constraint id AND the
   * status) so we never silently swallow a real domain-restriction
   * denial as "transient".
   */
  static boolean isMemberDomainPropagationError(@NotNull GoogleJsonResponseException e) {
    if (e.getStatusCode() != 400) {
      return false;
    }
    var sb = new StringBuilder();
    if (e.getMessage() != null) {
      sb.append(e.getMessage());
    }
    if (e.getDetails() != null) {
      if (e.getDetails().getMessage() != null) {
        sb.append('\n').append(e.getDetails().getMessage());
      }
      if (e.getDetails().getErrors() != null) {
        e.getDetails().getErrors().forEach(err -> {
          if (err.getMessage() != null) {
            sb.append('\n').append(err.getMessage());
          }
        });
      }
    }
    var haystack = sb.toString().toLowerCase();
    return haystack.contains("allowedpolicymemberdomains")
      || haystack.contains("not in permitted organization");
  }

  /**
   * Create a new, API-specific client.
   */
  abstract @NotNull AbstractGoogleJsonClient createClient() throws IOException;

  /**
   * Read IAM policy of resource.
   * <p>
   * Deriving classes should provide an overload that accepts a ResourceId
   * instead of a resource path.
   */
  protected GetIamPolicy getIamPolicy(
    @NotNull String fullResourcePath,
    @NotNull GetIamPolicyRequest content
  ) throws IOException {
    return new GetIamPolicy(createClient(), fullResourcePath, content);
  }

  /**
   * Set IAM policy on resource.
   * <p>
   * Deriving classes should provide an overload that accepts a ResourceId
   * instead of a resource path.
   */
  protected SetIamPolicy setIamPolicy(
    @NotNull String fullResourcePath,
    @NotNull SetIamPolicyRequest content
  ) throws IOException {
    return new SetIamPolicy(createClient(), fullResourcePath, content);
  }

  /**
   * Modify an IAM policy using the optimistic concurrency control-mechanism.
   */
  @SuppressWarnings("fallthrough")
  public void modifyIamPolicy(
    @NotNull String fullResourcePath,
    @NotNull Consumer<Policy> modify,
    @NotNull String requestReason
  ) throws AccessException, IOException {
    Preconditions.checkNotNull(fullResourcePath, "fullResourcePath");
    Preconditions.checkNotNull(modify, "modify");

    final var optionsV3 = new GetPolicyOptions().setRequestedPolicyVersion(3);

    try {
      var client = createClient();

      //
      // IAM policies use optimistic concurrency control, so we might need to perform
      // multiple attempts to update the policy.
      //
      int memberDomainRetries = 0;
      for (int attempt = 0; attempt < MAX_SET_IAM_POLICY_ATTEMPTS; attempt++) {
        //
        // Read current version of policy.
        //
        // NB. The API might return a v1 policy even if we
        // request a v3 policy.
        //
        var getRequest = new GetIamPolicy(
          client,
          fullResourcePath,
          new GetIamPolicyRequest()
            .setOptions(optionsV3));
        var policy = getRequest.execute();

        //
        // Make sure we're using v3; older versions don't support conditions.
        //
        policy.setVersion(3);

        //
        // Apply changes.
        //
        modify.accept(policy);

        try {
          var request = new SetIamPolicy(
            client,
            fullResourcePath,
            new SetIamPolicyRequest().setPolicy(policy));

          request.getRequestHeaders().set("x-goog-request-reason", requestReason);
          request.execute();

          //
          // Successful update -> quit loop.
          //
          return;
        }
        catch (GoogleJsonResponseException e) {
          if (e.getStatusCode() == 412) {
            //
            // Concurrent modification - back off and retry.
            //
            try {
              Thread.sleep(200);
            }
            catch (InterruptedException ignored) {
            }
          }
          else if (isMemberDomainPropagationError(e)
            && memberDomainRetries < MAX_MEMBER_DOMAIN_PROPAGATION_ATTEMPTS) {
            //
            // SECOP-1096: a just-provisioned group isn't resolvable by
            // the org-policy member-domain checker yet. Back off longer
            // than the 412 case (propagation is tens of seconds, not
            // milliseconds) and retry. Don't spend a concurrency-control
            // attempt on it — decrement so 412 retries stay available.
            //
            memberDomainRetries++;
            try {
              Thread.sleep(2000L << (memberDomainRetries - 1)); // 2s, 4s, 8s
            }
            catch (InterruptedException ignored) {
            }
            attempt--;
          }
          else {
            throw (GoogleJsonResponseException) e.fillInStackTrace();
          }
        }
      }

      throw new AlreadyExistsException(
        "Failed to update IAM bindings due to concurrent modifications");
    }
    catch (GoogleJsonResponseException e) {
      switch (e.getStatusCode()) {
        case 400:
          //
          // One possible reason for an INVALID_ARGUMENT error is that we've tried
          // to grant a role on a resource that cannot be granted on this type of resource.
          // If that's the case, provide a more descriptive error message.
          //
          if (e.getDetails() != null &&
            e.getDetails().getErrors() != null &&
            !e.getDetails().getErrors().isEmpty() &&
            isRoleNotGrantableErrorMessage(e.getDetails().getErrors().get(0).getMessage())) {
            throw new AccessDeniedException(
              String.format("Modifying IAM policy of '%s' failed because one of the " +
                "roles isn't compatible with this resource",
                fullResourcePath));
          }
          else {
            // Fallthrough.
          }

        case 401:
          throw new NotAuthenticatedException("Not authenticated", e);

        case 403:
          throw new AccessDeniedException(String.format(
            "Access to '%s' is denied", fullResourcePath),
            e);

        default:
          throw (GoogleJsonResponseException) e.fillInStackTrace();
      }
    }
  }

  //---------------------------------------------------------------------------
  // Request classes.
  //---------------------------------------------------------------------------

  static class GetIamPolicy extends AbstractGoogleJsonClientRequest<Policy> {
    protected GetIamPolicy(
      @NotNull AbstractGoogleJsonClient client,
      @NotNull String fullResourcePath,
      @NotNull GetIamPolicyRequest content
    ) {
      super(
        client,
        "POST",
        fullResourcePath + ":getIamPolicy",
        content,
        Policy.class);
    }
  }

  static class SetIamPolicy extends AbstractGoogleJsonClientRequest<Policy> {
    protected SetIamPolicy(
      @NotNull AbstractGoogleJsonClient client,
      @NotNull String fullResourcePath,
      @NotNull SetIamPolicyRequest content
    ) {
      super(
        client,
        "POST",
        fullResourcePath + ":setIamPolicy",
        content,
        Policy.class);
    }
  }
}