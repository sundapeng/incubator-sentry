/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.binding.hive.v2;

import java.util.List;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.ql.security.HiveAuthenticationProvider;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAccessController;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveAuthzSessionContext;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrincipal;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilege;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeInfo;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HivePrivilegeObject;
import org.apache.hadoop.hive.ql.security.authorization.plugin.HiveRoleGrant;
import org.apache.sentry.binding.hive.conf.HiveAuthzConf;
import org.apache.sentry.binding.hive.conf.HiveAuthzConf.AuthzConfVars;
import org.apache.sentry.binding.hive.v2.util.SentryAccessControlException;
import org.apache.sentry.provider.db.service.thrift.SentryPolicyServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;

/**
 * Abstract class to do access control commands,
 * e.g. grant/revoke privileges, grant/revoke role, create/drop role.
 */
public abstract class SentryAccessController implements HiveAccessController {
  public static final Logger LOG = LoggerFactory.getLogger(SentryAccessController.class);
  protected HiveAuthenticationProvider authenticator;
  protected String serverName;
  protected SentryPolicyServiceClient sentryClient;
  protected HiveConf conf;
  protected HiveAuthzConf authzConf;
  protected HiveAuthzSessionContext ctx;

  public SentryAccessController(
      HiveConf conf,
      HiveAuthzConf authzConf,
      HiveAuthenticationProvider authenticator,
      HiveAuthzSessionContext ctx) throws Exception {
    initilize(conf, authzConf, authenticator, ctx);
  }

  /**
   * initialize authenticator and hiveAuthzBinding.
   */
  protected void initilize(HiveConf conf,
      HiveAuthzConf authzConf,
      HiveAuthenticationProvider authenticator,
      HiveAuthzSessionContext ctx) throws Exception {
    Preconditions.checkNotNull(conf, "HiveConf cannot be null");
    Preconditions.checkNotNull(authzConf, "HiveAuthzConf cannot be null");
    Preconditions.checkNotNull(authenticator, "Hive authenticator provider cannot be null");
    Preconditions.checkNotNull(ctx, "HiveAuthzSessionContext cannot be null");

    this.conf = conf;
    this.authzConf = authzConf;
    this.authenticator = authenticator;
    this.ctx = ctx;
    this.serverName = Preconditions.checkNotNull(authzConf.get(AuthzConfVars.AUTHZ_SERVER_NAME.getVar()),
        "Config " + AuthzConfVars.AUTHZ_SERVER_NAME.getVar() + " is required");
  }

  /**
   * Hive statement: Grant privilege
   * GRANT
   *     priv_type [, priv_type ] ...
   *     ON table_or_view_name
   *     TO principal_specification [, principal_specification] ...
   *     [WITH GRANT OPTION];
   *
   * principal_specification
   *   : USER user
   *   | ROLE role
   *
   * priv_type
   *   : INSERT | SELECT | UPDATE | DELETE | ALL
   *
   * @param hivePrincipals
   * @param hivePrivileges
   * @param hivePrivObject
   * @param grantorPrincipal
   * @param grantOption
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void grantPrivileges(List<HivePrincipal> hivePrincipals,
      List<HivePrivilege> hivePrivileges, HivePrivilegeObject hivePrivObject,
      HivePrincipal grantorPrincipal, boolean grantOption) throws SentryAccessControlException;

  /**
   * Hive statement: Revoke privilege
   * REVOKE
   *     priv_type [, priv_type ] ...
   *     ON table_or_view_name
   *     FROM principal_specification [, principal_specification] ... ;
   *
   * principal_specification
   *   : USER user
   *   | ROLE role
   *
   * priv_type
   *   : INSERT | SELECT | UPDATE | DELETE | ALL
   *
   * @param hivePrincipals
   * @param hivePrivileges
   * @param hivePrivObject
   * @param grantorPrincipal
   * @param grantOption
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void revokePrivileges(List<HivePrincipal> hivePrincipals,
      List<HivePrivilege> hivePrivileges, HivePrivilegeObject hivePrivObject,
      HivePrincipal grantorPrincipal, boolean grantOption) throws SentryAccessControlException;

  /**
   * Hive statement: Create role
   * CREATE ROLE role_name;
   *
   * @param roleName
   * @param adminGrantor
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void createRole(String roleName, HivePrincipal adminGrantor)
      throws SentryAccessControlException;

  /**
   * Hive statement: Drop role
   * DROP ROLE role_name;
   *
   * @param roleName
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void dropRole(String roleName) throws SentryAccessControlException;

  /**
   * Hive statement: Grant role
   * GRANT role_name [, role_name] ...
   * TO principal_specification [, principal_specification] ...
   * [ WITH ADMIN OPTION ];
   *
   * principal_specification
   *   : USER user
   *   | ROLE role
   *
   * @param hivePrincipals
   * @param roles
   * @param grantOption
   * @param grantorPrinc
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void grantRole(List<HivePrincipal> hivePrincipals, List<String> roles,
      boolean grantOption, HivePrincipal grantorPrinc) throws SentryAccessControlException;

  /**
   * Hive statement: Revoke role
   * REVOKE [ADMIN OPTION FOR] role_name [, role_name] ...
   * FROM principal_specification [, principal_specification] ... ;
   *
   * principal_specification
   *   : USER user
   *   | ROLE role
   *
   * @param hivePrincipals
   * @param roles
   * @param grantOption
   * @param grantorPrinc
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void revokeRole(List<HivePrincipal> hivePrincipals,
      List<String> roles, boolean grantOption, HivePrincipal grantorPrinc)
          throws SentryAccessControlException;

  /**
   * Hive statement: Show roles
   * SHOW ROLES;
   *
   * @throws SentryAccessControlException
   */
  @Override
  public abstract List<String> getAllRoles() throws SentryAccessControlException;

  /**
   * Hive statement: Show grant
   * SHOW GRANT [principal_name] ON (ALL| ([TABLE] table_or_view_name);
   *
   * @param principal
   * @param privObj
   * @throws SentryAccessControlException
   */
  @Override
  public abstract List<HivePrivilegeInfo> showPrivileges(HivePrincipal principal,
      HivePrivilegeObject privObj) throws SentryAccessControlException;

  /**
   * Hive statement: Set role
   * SET ROLE (role_name|ALL);
   *
   * @param roleName
   * @throws SentryAccessControlException
   */
  @Override
  public abstract void setCurrentRole(String roleName) throws SentryAccessControlException;

  /**
   * Hive statement: Show current roles
   * SHOW CURRENT ROLES;
   *
   */
  @Override
  public abstract List<String> getCurrentRoleNames() ;

  /**
   * Hive statement: Set role privileges
   * SHOW PRINCIPALS role_name;
   *
   * @param roleName
   * @throws SentryAccessControlException
   */
  @Override
  public abstract List<HiveRoleGrant> getPrincipalGrantInfoForRole(String roleName)
      throws SentryAccessControlException;

  /**
   * Hive statement: Set role grant
   * SHOW ROLE GRANT (USER|ROLE) principal_name;
   *
   * @param principal
   * @throws SentryAccessControlException
   */
  @Override
  public abstract List<HiveRoleGrant> getRoleGrantInfoForPrincipal(
      HivePrincipal principal) throws SentryAccessControlException;

  /**
   * Apply configuration files for authorization V2
   *
   * @param hiveConf
   */
  @Override
  public abstract void applyAuthorizationConfigPolicy(HiveConf hiveConf);

}