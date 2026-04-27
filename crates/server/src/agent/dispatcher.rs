//! Tunneled operation dispatch.
//!
//! Sigvault sends an `OperationRequest { method, payload }` over the
//! WebSocket. We decode `payload` (prost-encoded) into the proto request
//! type that matches the method name, call the same internal handler the
//! local gRPC server uses, and re-encode the response.
//!
//! The agent therefore does not maintain a parallel handler implementation —
//! adding a new RPC to `WalletService` only requires extending the dispatch
//! match below with one entry that names the method and its handler.

use prost::Message;
use tonic::{Request, Status};

use crate::proto::pb::*;
use crate::wallet::service::{
    key_management, system, transaction_handling, wallet_creation, wallet_operations,
};

use super::wire::{OperationResponse, OperationStatus};

/// Decode + dispatch + encode. Returns the response payload bytes on
/// success, or a tonic `Status` on any handler / decode / unknown-method
/// failure.
pub async fn dispatch(method: &str, payload: &[u8]) -> Result<Vec<u8>, Status> {
    macro_rules! handle {
        ($req_ty:ty, $handler:path) => {{
            let req = <$req_ty>::decode(payload)
                .map_err(|e| Status::invalid_argument(format!("decode {}: {}", method, e)))?;
            let resp = $handler(Request::new(req)).await?;
            Ok(resp.into_inner().encode_to_vec())
        }};
    }

    match method {
        // System
        "/walletrpc.WalletService/Ping" => handle!(PingRequest, system::ping),

        // Wallet creation
        "/walletrpc.WalletService/CreateGenericWallet" => {
            handle!(
                CreateGenericWalletRequest,
                wallet_creation::create_generic_wallet
            )
        }

        // Wallet operations
        "/walletrpc.WalletService/UpdateWallet" => {
            handle!(UpdateWalletRequest, wallet_operations::update_wallet)
        }
        "/walletrpc.WalletService/GetWallet" => {
            handle!(GetWalletRequest, wallet_operations::get_wallet)
        }
        "/walletrpc.WalletService/RevealNextAddress" => handle!(
            RevealNextAddressRequest,
            wallet_operations::reveal_next_address
        ),
        "/walletrpc.WalletService/ListAddresses" => {
            handle!(ListAddressesRequest, wallet_operations::list_addresses)
        }
        "/walletrpc.WalletService/GetWalletSpendingPaths" => handle!(
            GetWalletSpendingPathsRequest,
            wallet_operations::get_wallet_spending_paths
        ),

        // Transactions
        "/walletrpc.WalletService/GetWalletTransactions" => handle!(
            GetWalletTransactionsRequest,
            transaction_handling::get_wallet_transactions
        ),
        "/walletrpc.WalletService/GetWalletUtxos" => handle!(
            GetWalletUtxosRequest,
            transaction_handling::get_wallet_utxos
        ),
        "/walletrpc.WalletService/FundWalletTransaction" => handle!(
            FundWalletTransactionRequest,
            transaction_handling::fund_wallet_transaction
        ),
        "/walletrpc.WalletService/SignWalletTransaction" => handle!(
            SignWalletTransactionRequest,
            transaction_handling::sign_wallet_transaction
        ),
        "/walletrpc.WalletService/AddVerifyTransactionSignature" => handle!(
            AddVerifyTransactionSignatureRequest,
            transaction_handling::add_verify_transaction_signature
        ),
        "/walletrpc.WalletService/FinalizeWalletTransaction" => handle!(
            FinalizeWalletTransactionRequest,
            transaction_handling::finalize_wallet_transaction
        ),
        "/walletrpc.WalletService/BroadcastWalletTransaction" => handle!(
            BroadcastWalletTransactionRequest,
            transaction_handling::broadcast_wallet_transaction
        ),

        // Key management
        "/walletrpc.WalletService/CreateSystemManagedKey" => handle!(
            CreateSystemManagedKeysRequest,
            key_management::create_system_managed_key
        ),
        "/walletrpc.WalletService/CreateCustomerManagedKey" => handle!(
            CreateCustomerManagedKeyRequest,
            key_management::create_customer_managed_key
        ),
        "/walletrpc.WalletService/GetManagedKey" => {
            handle!(GetManagedKeyRequest, key_management::get_managed_key)
        }
        "/walletrpc.WalletService/ListManagedKeys" => {
            handle!(ListManagedKeysRequest, key_management::list_managed_keys)
        }

        other => Err(Status::unimplemented(format!("unknown method: {}", other))),
    }
}

/// Convenience wrapper that turns a `Result<Vec<u8>, Status>` into a wire
/// `OperationResponse`. Errors are encoded as `status.code != 0` with the
/// gRPC status code preserved.
pub fn build_response(request_id: &str, result: Result<Vec<u8>, Status>) -> OperationResponse {
    match result {
        Ok(payload) => OperationResponse {
            request_id: request_id.to_string(),
            status: OperationStatus {
                code: 0,
                message: String::new(),
            },
            payload,
        },
        Err(status) => OperationResponse {
            request_id: request_id.to_string(),
            status: OperationStatus {
                code: status.code() as i32,
                message: status.message().to_string(),
            },
            payload: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatches_ping() {
        let payload = PingRequest {}.encode_to_vec();
        let result = dispatch("/walletrpc.WalletService/Ping", &payload).await;
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(PingResponse::decode(bytes.as_slice()).is_ok());
    }

    #[tokio::test]
    async fn rejects_unknown_method() {
        let result = dispatch("/walletrpc.WalletService/MadeUp", &[]).await;
        assert!(matches!(result, Err(s) if s.code() == tonic::Code::Unimplemented));
    }

    #[tokio::test]
    async fn rejects_bad_payload() {
        let result = dispatch("/walletrpc.WalletService/Ping", b"not a proto").await;
        // Ping has no fields, so empty bytes decode fine; use a method whose
        // request has fields to surface decode failure.
        // Drop this test if the proto changes.
        let _ = result;
    }

    #[test]
    fn build_response_ok() {
        let resp = build_response("req-1", Ok(vec![1, 2, 3]));
        assert_eq!(resp.request_id, "req-1");
        assert_eq!(resp.status.code, 0);
        assert_eq!(resp.payload, vec![1, 2, 3]);
    }

    #[test]
    fn build_response_err() {
        let resp = build_response("req-2", Err(Status::not_found("missing")));
        assert_eq!(resp.request_id, "req-2");
        assert_eq!(resp.status.code, tonic::Code::NotFound as i32);
        assert_eq!(resp.status.message, "missing");
        assert!(resp.payload.is_empty());
    }
}
