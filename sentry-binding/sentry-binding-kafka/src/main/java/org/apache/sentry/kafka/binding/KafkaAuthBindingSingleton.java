/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sentry.kafka.binding;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.sentry.kafka.conf.KafkaAuthConf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

public class KafkaAuthBindingSingleton {
  private static Logger log = LoggerFactory.getLogger(KafkaAuthBindingSingleton.class);
  private static KafkaAuthBindingSingleton instance = null;

  private KafkaAuthBinding binding;

  private KafkaAuthBindingSingleton(String sentry_site) {
    try {
      KafkaAuthConf conf = loadAuthzConf(sentry_site);
      binding = new KafkaAuthBinding(conf);
      log.info("KafkaAuthBinding created successfully");
    } catch (Exception ex) {
      log.error("Unable to create KafkaAuthBinding", ex);
      throw new RuntimeException("Unable to create KafkaAuthBinding: " + ex.getMessage(), ex);
    }
  }

  private KafkaAuthConf loadAuthzConf(String sentry_site) {
    if (Strings.isNullOrEmpty(sentry_site)) {
      throw new IllegalArgumentException("Configuration key " + KafkaAuthConf.SENTRY_KAFKA_SITE_URL
          + " value '" + sentry_site + "' is invalid.");
    }

    KafkaAuthConf kafkaAuthConf = null;
    try {
      kafkaAuthConf = new KafkaAuthConf(new URL(sentry_site));
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Configuration key " + KafkaAuthConf.SENTRY_KAFKA_SITE_URL
          + " specifies a malformed URL '" + sentry_site + "'", e);
    }
    return kafkaAuthConf;
  }

  public static KafkaAuthBindingSingleton getInstance(String sentry_site) {
    if (instance == null) {
      synchronized (KafkaAuthBindingSingleton.class) {
        if (instance == null) {
          instance = new KafkaAuthBindingSingleton(sentry_site);
        }
      }
    }
    return instance;
  }

  public KafkaAuthBinding getAuthBinding() {
    return binding;
  }
}
