//! Read dispatch keeps private artifact projection ahead of evidence or file sinks.
use super::{
    AuthCredential, CallInput, CapabilityV1, CloudflareError, CloudflareResponseV1,
    EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID, Executor, Path, Result,
    is_email_routing_rules_list_capability, is_r2_buckets_list_capability,
    validate_d1_export_output_path,
};

impl Executor {
    pub async fn execute_read(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
    ) -> Result<CloudflareResponseV1> {
        if capability.id == cfctl_core::WORKER_VERSION_ARTIFACT_DIGEST_ID {
            return self
                .execute_worker_version_artifact_digest(capability, input, credential)
                .await;
        }
        if capability.r2_log_retrieval.is_some() {
            return Err(CloudflareError::R2LogCredentialsRequired);
        }
        let request = self.builder.build(capability, input)?;
        if is_email_routing_rules_list_capability(capability) {
            return self
                .execute_email_routing_rules_read(
                    &request,
                    credential,
                    capability.id == EMAIL_ROUTING_ACCOUNT_RULES_LIST_CAPABILITY_ID,
                )
                .await;
        }
        if is_r2_buckets_list_capability(capability) {
            return self
                .execute_r2_buckets_list_read(&request, credential)
                .await;
        }
        self.send_paginated(&request, credential).await
    }

    /// Executes a bounded analytics read and writes only the declared output to
    /// a newly-created mode-0600 file. The returned envelope contains a hash
    /// receipt instead of duplicating query rows on stdout.
    pub async fn execute_read_to_file(
        &self,
        capability: &CapabilityV1,
        input: &CallInput,
        credential: &AuthCredential,
        output_path: &Path,
    ) -> Result<CloudflareResponseV1> {
        if capability.id == cfctl_core::WORKER_VERSION_ARTIFACT_DIGEST_ID {
            return Err(CloudflareError::InvalidRequestBody(
                "Worker module bytes cannot be written to an output file".to_owned(),
            ));
        }

        if capability.r2_log_retrieval.is_some() {
            return Err(CloudflareError::R2LogCredentialsRequired);
        }
        if capability.d1_full_export.is_some() {
            let request = self.builder.build(capability, input)?;
            let output_path = validate_d1_export_output_path(output_path)?;
            return Box::pin(self.execute_d1_full_export_to_file(
                &request,
                credential,
                &output_path,
            ))
            .await;
        }
        if capability.analytics_query.is_none() {
            return Err(CloudflareError::InvalidAnalyticsQuery(
                "file output is restricted to bounded analytics capabilities".to_owned(),
            ));
        }
        let request = self.builder.build(capability, input)?;
        self.send_paginated_with_output(&request, credential, Some(output_path))
            .await
    }
}
