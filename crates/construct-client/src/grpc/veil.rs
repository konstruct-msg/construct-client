//! `VeilService`: capabilities for the fronts, issued to this signed-in device (iOS
//! `VeilServiceClient`).

use prost::Message;

use crate::proto::services::v1::{
    IssueBootstrapVoucherRequest, IssueBootstrapVoucherResponse, IssueVeilCapabilityRequest,
    IssueVeilCapabilityResponse,
};

use super::client::GrpcClient;
use super::error::GrpcError;
use super::paths;

/// `IssueVeilCapability`, signed in. With `veil_pk` the capability is key-bound (v3).
pub async fn issue_veil_capability(
    client: &GrpcClient,
    request: &IssueVeilCapabilityRequest,
) -> Result<IssueVeilCapabilityResponse, GrpcError> {
    let bytes = client
        .unary(paths::VEIL_ISSUE_CAPABILITY, &request.encode_to_vec())
        .await?;
    IssueVeilCapabilityResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("IssueVeilCapability decode: {e}")))
}

/// `IssueBootstrapVoucher`, signed in: a short-lived link to one front, for another device.
pub async fn issue_bootstrap_voucher(
    client: &GrpcClient,
) -> Result<IssueBootstrapVoucherResponse, GrpcError> {
    let bytes = client
        .unary(
            paths::VEIL_ISSUE_VOUCHER,
            &IssueBootstrapVoucherRequest::default().encode_to_vec(),
        )
        .await?;
    IssueBootstrapVoucherResponse::decode(bytes.as_slice())
        .map_err(|e| GrpcError::transport(format!("IssueBootstrapVoucher decode: {e}")))
}
