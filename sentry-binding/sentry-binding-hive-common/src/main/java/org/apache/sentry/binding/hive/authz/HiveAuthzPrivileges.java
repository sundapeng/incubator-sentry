/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.binding.hive.authz;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import org.apache.sentry.core.model.db.DBModelAction;
import org.apache.sentry.core.model.db.DBModelAuthorizable.AuthorizableType;

/**
 * Hive objects with required access privileges mapped to auth provider privileges
 */
public class HiveAuthzPrivileges {

  /**
   * Operation type used for privilege granting
   */
  public static enum HiveOperationType {
    UNKNOWN,
    DDL,
    DML,
    DATA_LOAD,
    DATA_UNLOAD,
    QUERY,
    INFO
  };

  /**
   * scope of the operation. The auth provider interface has different methods
   * for some of these. Hence we want to be able to identity the auth scope of
   * a statement eg. server level or DB level etc.
   */
  public static enum HiveOperationScope {
    UNKNOWN,
    SERVER,
    DATABASE,
    TABLE,
    FUNCTION,
    CONNECT,
    COLUMN
  }

  public static enum HiveExtendedOperation {
    TRANSFORM,
    RESOURCE
  }

  public static class AuthzPrivilegeBuilder {
    private final Map<AuthorizableType, EnumSet<DBModelAction>> inputPrivileges =
        new HashMap<AuthorizableType ,EnumSet<DBModelAction>>();
    private final Map<AuthorizableType,EnumSet<DBModelAction>> outputPrivileges =
        new HashMap<AuthorizableType,EnumSet<DBModelAction>>();
    private HiveOperationType operationType;
    private HiveOperationScope operationScope;

    public AuthzPrivilegeBuilder addInputObjectPriviledge(AuthorizableType inputObjectType, EnumSet<DBModelAction> inputPrivilege) {
      inputPrivileges.put(inputObjectType, inputPrivilege);
      return this;
    }

    public AuthzPrivilegeBuilder addOutputEntityPriviledge(AuthorizableType outputEntityType, EnumSet<DBModelAction> outputPrivilege) {
      outputPrivileges.put(outputEntityType, outputPrivilege);
      return this;
    }

    public AuthzPrivilegeBuilder addOutputObjectPriviledge(AuthorizableType outputObjectType, EnumSet<DBModelAction> outputPrivilege) {
      outputPrivileges.put(outputObjectType, outputPrivilege);
      return this;
    }

    public AuthzPrivilegeBuilder setOperationType(HiveOperationType operationType) {
      this.operationType = operationType;
      return this;
    }

    public AuthzPrivilegeBuilder setOperationScope(HiveOperationScope operationScope) {
      this.operationScope = operationScope;
      return this;
    }

    public HiveAuthzPrivileges build() {
      if (operationScope.equals(HiveOperationScope.UNKNOWN)) {
        throw new UnsupportedOperationException("Operation scope is not set");
      }

      if (operationType.equals(HiveOperationType.UNKNOWN)) {
        throw new UnsupportedOperationException("Operation scope is not set");
      }

      return new HiveAuthzPrivileges(inputPrivileges, outputPrivileges, operationType, operationScope);
    }
  }

  private final Map<AuthorizableType,EnumSet<DBModelAction>> inputPrivileges =
      new HashMap<AuthorizableType,EnumSet<DBModelAction>>();
  private final Map<AuthorizableType,EnumSet<DBModelAction>>  outputPrivileges =
      new HashMap<AuthorizableType,EnumSet<DBModelAction>>();
  private final HiveOperationType operationType;
  private final HiveOperationScope operationScope;

  protected HiveAuthzPrivileges(Map<AuthorizableType,EnumSet<DBModelAction>> inputPrivileges,
      Map<AuthorizableType,EnumSet<DBModelAction>> outputPrivileges, HiveOperationType operationType,
      HiveOperationScope operationScope) {
    this.inputPrivileges.putAll(inputPrivileges);
    this.outputPrivileges.putAll(outputPrivileges);
    this.operationScope = operationScope;
    this.operationType = operationType;
  }

  /**
   * @return the inputPrivileges
   */
  public Map<AuthorizableType, EnumSet<DBModelAction>> getInputPrivileges() {
    return inputPrivileges;
  }

  /**
   * @return the outputPrivileges
   */
  public Map<AuthorizableType, EnumSet<DBModelAction>> getOutputPrivileges() {
    return outputPrivileges;
  }

  /**
   * @return the operationType
   */
  public HiveOperationType getOperationType() {
    return operationType;
  }

  /**
   * @return the operationScope
   */
  public HiveOperationScope getOperationScope() {
    return operationScope;
  }
}
