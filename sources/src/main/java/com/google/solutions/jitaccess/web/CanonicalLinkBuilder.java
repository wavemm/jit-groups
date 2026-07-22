//
// Copyright 2026 Google LLC
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

package com.google.solutions.jitaccess.web;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.net.URI;
import java.util.Locale;

/**
 * Wavemm fork: link builder that rewrites generated links to a canonical
 * public URL when — and only when — the request arrived on the app's
 * default appspot host.
 *
 * <p>Generated links (e.g. the approval link fanned out to reviewers in
 * Slack DMs) otherwise inherit whatever host the requester was browsing:
 * a request submitted on the default appspot host sends every reviewer
 * an appspot link even though the app has a custom domain.
 *
 * <p>Versioned App Engine hosts (rev-…-dot-…appspot.com) are deliberately
 * left untouched: they are the staging surface (deploys with
 * promote_traffic=false are smoke-tested on the versioned URL, see
 * SLACK_INTEGRATION.md in wavemm-iam), and rewriting them would point
 * staging-generated links at the traffic-promoted production version.
 * Custom domains and localhost pass through unchanged, too.
 */
public class CanonicalLinkBuilder implements LinkBuilder {
  private final @Nullable URI canonicalBaseUri;
  private final @NotNull String fallbackScheme;

  public CanonicalLinkBuilder(
    @Nullable URI canonicalBaseUri,
    @NotNull String fallbackScheme
  ) {
    this.canonicalBaseUri = canonicalBaseUri;
    this.fallbackScheme = fallbackScheme;
  }

  @Override
  public UriBuilder absoluteUriBuilder(@NotNull UriInfo uriInfo) {
    if (this.canonicalBaseUri != null &&
      isDefaultAppspotHost(uriInfo.getBaseUri().getHost())) {
      return UriBuilder.fromUri(this.canonicalBaseUri);
    }

    return uriInfo
      .getBaseUriBuilder()
      .scheme(this.fallbackScheme);
  }

  /**
   * The app's default appspot hosts (project.appspot.com or
   * project.REGION.r.appspot.com) route to the traffic-promoted version,
   * so links on them can safely be canonicalized. Versioned hosts always
   * contain a {@code -dot-} separator (VERSION-dot-SERVICE-dot-project…)
   * and must never match.
   */
  static boolean isDefaultAppspotHost(@Nullable String host) {
    if (host == null) {
      return false;
    }

    var normalized = host.toLowerCase(Locale.ROOT);
    return normalized.endsWith(".appspot.com") && !normalized.contains("-dot-");
  }
}
