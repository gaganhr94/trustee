// Copyright (c) 2026 Confidential Containers Contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// AWS resource backend. Fetches secret material from AWS Secrets Manager
// (AWS KMS proper only operates on keys, not on arbitrary secret blobs;
// Secrets Manager is the closest analog to the Aliyun KMS Instance secrets
// API that backs `aliyun_kms.rs`).

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{anyhow, bail, Context, Result};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct AwsKmsBackendConfig {
    /// AWS region (e.g. `us-east-1`). If omitted, the default credential chain
    /// resolves it (env `AWS_REGION`, profile, IMDS, …).
    #[serde(default)]
    pub region: Option<String>,

    /// Optional endpoint override. Useful for FIPS endpoints, GovCloud, or
    /// LocalStack in tests.
    #[serde(default)]
    pub endpoint_url: Option<String>,
}

pub struct AwsKmsBackend {
    client: SecretsManagerClient,
}

#[async_trait::async_trait]
impl StorageBackend for AwsKmsBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        info!(
            "Use AWS Secrets Manager backend. Ignore {}/{}",
            resource_desc.repository_name, resource_desc.resource_type
        );
        let name = resource_desc.resource_tag;

        let response = self
            .client
            .get_secret_value()
            .secret_id(name.as_str())
            .send()
            .await
            .with_context(|| format!("failed to get secret '{name}' from AWS Secrets Manager"))?;

        if let Some(blob) = response.secret_binary {
            return Ok(blob.into_inner());
        }
        if let Some(string) = response.secret_string {
            return Ok(string.into_bytes());
        }
        Err(anyhow!(
            "AWS Secrets Manager returned no value for secret '{name}'"
        ))
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        bail!("AWS Secrets Manager backend does not support write operations; provision secrets via AWS APIs")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        bail!("AWS Secrets Manager backend does not support delete operations; manage secret lifecycle via AWS APIs")
    }
}

impl AwsKmsBackend {
    pub async fn new(config: &AwsKmsBackendConfig) -> Result<Self> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(region) = &config.region {
            loader = loader.region(Region::new(region.clone()));
        }
        if let Some(endpoint) = &config.endpoint_url {
            loader = loader.endpoint_url(endpoint.clone());
        }
        let aws_config = loader.load().await;
        let client = SecretsManagerClient::new(&aws_config);
        Ok(Self { client })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_config() {
        let cfg: AwsKmsBackendConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.region, None);
        assert_eq!(cfg.endpoint_url, None);
    }

    #[test]
    fn deserialize_full_config() {
        let cfg: AwsKmsBackendConfig = toml::from_str(
            r#"
            region = "us-west-2"
            endpoint_url = "https://secretsmanager-fips.us-west-2.amazonaws.com"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.region.as_deref(), Some("us-west-2"));
        assert_eq!(
            cfg.endpoint_url.as_deref(),
            Some("https://secretsmanager-fips.us-west-2.amazonaws.com")
        );
    }
}
