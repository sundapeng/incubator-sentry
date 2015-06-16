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

package org.apache.sentry.service.thrift;

import java.lang.reflect.Proxy;

import org.apache.hadoop.conf.Configuration;
import org.apache.sentry.provider.db.service.thrift.SentryPolicyServiceClient;
import org.apache.sentry.provider.db.service.thrift.SentryPolicyServiceClientDefaultImpl;
import org.apache.sentry.service.thrift.ServiceConstants.ClientConfig;

public class SentryServiceClientFactory {

  private SentryServiceClientFactory() {
  }

  public static SentryPolicyServiceClient create(Configuration conf) throws Exception {
    boolean haEnabled = conf.getBoolean(ClientConfig.SERVER_HA_ENABLED, false);
    boolean pooled = conf.getBoolean(ClientConfig.SENTRY_POOL_ENABLED, false);
    if (pooled) {
      return (SentryPolicyServiceClient) Proxy
          .newProxyInstance(SentryPolicyServiceClientDefaultImpl.class.getClassLoader(),
              SentryPolicyServiceClientDefaultImpl.class.getInterfaces(),
              new PoolClientInvocationHandler(conf));
    } else if (haEnabled) {
      return (SentryPolicyServiceClient) Proxy
          .newProxyInstance(SentryPolicyServiceClientDefaultImpl.class.getClassLoader(),
              SentryPolicyServiceClientDefaultImpl.class.getInterfaces(),
              new HAClientInvocationHandler(conf));
    } else {
      return new SentryPolicyServiceClientDefaultImpl(conf);
    }
  }

}