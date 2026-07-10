//
// Copyright 2026 Wave Mobile Money / wavemm fork
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//

package com.google.solutions.jitaccess.apis.clients;

import com.google.api.client.googleapis.json.GoogleJsonError;
import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpResponseException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link AbstractIamClient#isMemberDomainPropagationError}
 * (SECOP-1096). The retry loop itself needs a live API and is covered by
 * ITestAbstractIamClient; here we pin the classification predicate that
 * decides whether a 400 is the transient new-group propagation race.
 */
public class TestAbstractIamClient {

  private static GoogleJsonResponseException error(int status, String detailMessage) {
    var builder = new HttpResponseException.Builder(status, "status", new HttpHeaders());
    var details = new GoogleJsonError();
    if (detailMessage != null) {
      details.setMessage(detailMessage);
    }
    return new GoogleJsonResponseException(builder, details);
  }

  @Test
  public void isMemberDomainPropagationError_whenDomainViolationOn400() {
    assertTrue(AbstractIamClient.isMemberDomainPropagationError(
      error(400,
        "User jit.production.gcp.serviceusage-admin@roles.wave.com is not "
          + "in permitted organization.")));
  }

  @Test
  public void isMemberDomainPropagationError_whenConstraintIdPresent() {
    assertTrue(AbstractIamClient.isMemberDomainPropagationError(
      error(400, "constraints/iam.allowedPolicyMemberDomains violated")));
  }

  @Test
  public void isMemberDomainPropagationError_falseForUnrelated400() {
    assertFalse(AbstractIamClient.isMemberDomainPropagationError(
      error(400, "Invalid argument: role does not exist")));
  }

  @Test
  public void isMemberDomainPropagationError_falseWhenNotA400() {
    // Same message shape but a 403 is a real denial, not the race.
    assertFalse(AbstractIamClient.isMemberDomainPropagationError(
      error(403, "not in permitted organization")));
  }

  @Test
  public void isMemberDomainPropagationError_falseWhenNoDetail() {
    assertFalse(AbstractIamClient.isMemberDomainPropagationError(error(400, null)));
  }
}
