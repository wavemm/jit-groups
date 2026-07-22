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
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class TestCanonicalLinkBuilder {
  private static final URI CANONICAL_URI = URI.create("https://pam.example.com");

  private static UriInfo uriInfoFor(@NotNull String baseUri) {
    var uriInfo = Mockito.mock(UriInfo.class);
    when(uriInfo.getBaseUri())
      .thenReturn(URI.create(baseUri));
    when(uriInfo.getBaseUriBuilder())
      .thenAnswer(a -> UriBuilder.fromUri(baseUri));
    return uriInfo;
  }

  // -------------------------------------------------------------------------
  // absoluteUriBuilder.
  // -------------------------------------------------------------------------

  @Test
  public void absoluteUriBuilder_whenDefaultAppspotHost_thenUsesCanonicalUri() {
    var linkBuilder = new CanonicalLinkBuilder(CANONICAL_URI, "https");

    var uri = linkBuilder
      .absoluteUriBuilder(uriInfoFor("https://project.nw.r.appspot.com/"))
      .path("/")
      .build();

    assertEquals(URI.create("https://pam.example.com/"), uri);
  }

  @Test
  public void absoluteUriBuilder_whenLegacyAppspotHost_thenUsesCanonicalUri() {
    var linkBuilder = new CanonicalLinkBuilder(CANONICAL_URI, "https");

    var uri = linkBuilder
      .absoluteUriBuilder(uriInfoFor("https://project.appspot.com/"))
      .path("/")
      .build();

    assertEquals(URI.create("https://pam.example.com/"), uri);
  }

  /**
   * Versioned hosts are the staging surface (promote_traffic=false
   * deploys are smoke-tested on them) — links they generate must keep
   * pointing at the staged version, not the promoted one.
   */
  @Test
  public void absoluteUriBuilder_whenVersionedAppspotHost_thenKeepsRequestHost() {
    var linkBuilder = new CanonicalLinkBuilder(CANONICAL_URI, "https");

    var uri = linkBuilder
      .absoluteUriBuilder(uriInfoFor(
        "https://rev-abc123-dot-default-dot-project.nw.r.appspot.com/"))
      .path("/")
      .build();

    assertEquals(
      URI.create("https://rev-abc123-dot-default-dot-project.nw.r.appspot.com/"),
      uri);
  }

  @Test
  public void absoluteUriBuilder_whenCustomDomain_thenKeepsRequestHost() {
    var linkBuilder = new CanonicalLinkBuilder(CANONICAL_URI, "https");

    var uri = linkBuilder
      .absoluteUriBuilder(uriInfoFor("https://pam.other.example.com/"))
      .path("/")
      .build();

    assertEquals(URI.create("https://pam.other.example.com/"), uri);
  }

  @Test
  public void absoluteUriBuilder_whenCanonicalUriNotConfigured_thenKeepsRequestHost() {
    var linkBuilder = new CanonicalLinkBuilder(null, "https");

    var uri = linkBuilder
      .absoluteUriBuilder(uriInfoFor("http://project.nw.r.appspot.com/"))
      .path("/")
      .build();

    assertEquals(URI.create("https://project.nw.r.appspot.com/"), uri);
  }

  @Test
  public void absoluteUriBuilder_whenDevelopment_thenKeepsHttpScheme() {
    var linkBuilder = new CanonicalLinkBuilder(null, "http");

    var uri = linkBuilder
      .absoluteUriBuilder(uriInfoFor("http://localhost:8080/"))
      .path("/")
      .build();

    assertEquals(URI.create("http://localhost:8080/"), uri);
  }

  // -------------------------------------------------------------------------
  // isDefaultAppspotHost.
  // -------------------------------------------------------------------------

  @Test
  public void isDefaultAppspotHost() {
    assertTrue(CanonicalLinkBuilder.isDefaultAppspotHost(
      "project.appspot.com"));
    assertTrue(CanonicalLinkBuilder.isDefaultAppspotHost(
      "project.nw.r.appspot.com"));
    assertTrue(CanonicalLinkBuilder.isDefaultAppspotHost(
      "PROJECT.NW.R.APPSPOT.COM"));

    assertFalse(CanonicalLinkBuilder.isDefaultAppspotHost(null));
    assertFalse(CanonicalLinkBuilder.isDefaultAppspotHost(
      "rev-abc123-dot-default-dot-project.nw.r.appspot.com"));
    assertFalse(CanonicalLinkBuilder.isDefaultAppspotHost(
      "pam.example.com"));
    assertFalse(CanonicalLinkBuilder.isDefaultAppspotHost(
      "localhost"));
    assertFalse(CanonicalLinkBuilder.isDefaultAppspotHost(
      "project.appspot.com.evil.example.com"));
  }
}
