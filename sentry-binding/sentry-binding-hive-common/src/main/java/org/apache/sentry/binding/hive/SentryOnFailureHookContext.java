/*
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

package org.apache.sentry.binding.hive;

import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.ql.hooks.ReadEntity;
import org.apache.hadoop.hive.ql.hooks.WriteEntity;
import org.apache.hadoop.hive.ql.metadata.AuthorizationException;
import org.apache.hadoop.hive.ql.plan.HiveOperation;
import org.apache.sentry.core.model.db.AccessURI;
import org.apache.sentry.core.model.db.Database;
import org.apache.sentry.core.model.db.Table;

/**
 * Context information provided by Access to implementations
 * of AccessOnFailureHook
 */
public interface SentryOnFailureHookContext  {

  /**
   * @return the command attempted by user
   */
  String getCommand();

  /**
    * @return the set of read entities
    */
  Set<ReadEntity> getInputs();

  /**
   * @return the set of write entities
   */
  Set<WriteEntity> getOutputs();

  /**
   * @return the operation
   */
  HiveOperation getHiveOp();

  /**
   * @return the user name
   */
  String getUserName();

  /**
   * @return the ip address
   */
  String getIpAddress();

  /**
   * @return the database object
   */
  Database getDatabase();

  /**
   * @return the table object
   */
  Table getTable();

  /**
   * @return the udf URI
   */
  AccessURI getUdfURI();

  /**
   * @return the partition URI
   */
  AccessURI getPartitionURI();

  /**
   * @return the authorization failure exception
   */
  AuthorizationException getException();

  /**
   * @return the config
   */
  Configuration getConf();

}
