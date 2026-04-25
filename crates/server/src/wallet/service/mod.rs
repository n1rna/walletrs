// Module declarations
pub mod auth;
pub mod key_management;
pub mod middleware;
pub mod system;
pub mod transaction_handling;
pub mod wallet_creation;
pub mod wallet_operations;

use crate::proto::pb::wallet_service_server::WalletService;
use crate::proto::pb::{
    AddVerifyTransactionSignatureRequest,
    AddVerifyTransactionSignatureResponse,
    BroadcastWalletTransactionRequest,
    BroadcastWalletTransactionResponse,
    CreateCustomerManagedKeyRequest,
    CreateCustomerManagedKeyResponse,
    // Wallet creation
    CreateGenericWalletRequest,
    CreateGenericWalletResponse,
    // Key management
    CreateSystemManagedKeysRequest,
    CreateSystemManagedKeysResponse,
    FinalizeWalletTransactionRequest,
    FinalizeWalletTransactionResponse,
    FundWalletTransactionRequest,
    FundWalletTransactionResponse,
    GetManagedKeyRequest,
    GetManagedKeyResponse,
    GetWalletRequest,
    GetWalletResponse,
    GetWalletSpendingPathsRequest,
    GetWalletSpendingPathsResponse,
    // Transaction handling
    GetWalletTransactionsRequest,
    GetWalletTransactionsResponse,
    GetWalletUtxosRequest,
    GetWalletUtxosResponse,
    ListAddressesRequest,
    ListAddressesResponse,
    ListManagedKeysRequest,
    ListManagedKeysResponse,
    // System
    PingRequest,
    PingResponse,
    RevealNextAddressRequest,
    RevealNextAddressResponse,
    SignWalletTransactionRequest,
    SignWalletTransactionResponse,
    // Wallet operations
    UpdateWalletRequest,
    UpdateWalletResponse,
};
use tonic::{Request, Response, Status};

#[derive(Debug, Default)]
pub struct WalletRPC {}

#[tonic::async_trait]
impl WalletService for WalletRPC {
    // System methods
    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        system::ping(request).await
    }

    // Wallet creation methods
    async fn create_generic_wallet(
        &self,
        request: Request<CreateGenericWalletRequest>,
    ) -> Result<Response<CreateGenericWalletResponse>, Status> {
        wallet_creation::create_generic_wallet(request).await
    }

    // Wallet operations methods
    async fn update_wallet(
        &self,
        request: Request<UpdateWalletRequest>,
    ) -> Result<Response<UpdateWalletResponse>, Status> {
        wallet_operations::update_wallet(request).await
    }

    async fn get_wallet(
        &self,
        request: Request<GetWalletRequest>,
    ) -> Result<Response<GetWalletResponse>, Status> {
        wallet_operations::get_wallet(request).await
    }

    async fn reveal_next_address(
        &self,
        request: Request<RevealNextAddressRequest>,
    ) -> Result<Response<RevealNextAddressResponse>, Status> {
        wallet_operations::reveal_next_address(request).await
    }

    async fn list_addresses(
        &self,
        request: Request<ListAddressesRequest>,
    ) -> Result<Response<ListAddressesResponse>, Status> {
        wallet_operations::list_addresses(request).await
    }

    // Transaction handling methods
    async fn get_wallet_transactions(
        &self,
        request: Request<GetWalletTransactionsRequest>,
    ) -> Result<Response<GetWalletTransactionsResponse>, Status> {
        transaction_handling::get_wallet_transactions(request).await
    }

    async fn get_wallet_utxos(
        &self,
        request: Request<GetWalletUtxosRequest>,
    ) -> Result<Response<GetWalletUtxosResponse>, Status> {
        transaction_handling::get_wallet_utxos(request).await
    }

    async fn fund_wallet_transaction(
        &self,
        request: Request<FundWalletTransactionRequest>,
    ) -> Result<Response<FundWalletTransactionResponse>, Status> {
        transaction_handling::fund_wallet_transaction(request).await
    }

    async fn add_verify_transaction_signature(
        &self,
        request: Request<AddVerifyTransactionSignatureRequest>,
    ) -> Result<Response<AddVerifyTransactionSignatureResponse>, Status> {
        transaction_handling::add_verify_transaction_signature(request).await
    }

    async fn finalize_wallet_transaction(
        &self,
        request: Request<FinalizeWalletTransactionRequest>,
    ) -> Result<Response<FinalizeWalletTransactionResponse>, Status> {
        transaction_handling::finalize_wallet_transaction(request).await
    }

    async fn sign_wallet_transaction(
        &self,
        request: Request<SignWalletTransactionRequest>,
    ) -> Result<Response<SignWalletTransactionResponse>, Status> {
        transaction_handling::sign_wallet_transaction(request).await
    }

    async fn broadcast_wallet_transaction(
        &self,
        request: Request<BroadcastWalletTransactionRequest>,
    ) -> Result<Response<BroadcastWalletTransactionResponse>, Status> {
        transaction_handling::broadcast_wallet_transaction(request).await
    }

    // Key management methods
    async fn create_system_managed_key(
        &self,
        request: Request<CreateSystemManagedKeysRequest>,
    ) -> Result<Response<CreateSystemManagedKeysResponse>, Status> {
        key_management::create_system_managed_key(request).await
    }

    async fn create_customer_managed_key(
        &self,
        request: Request<CreateCustomerManagedKeyRequest>,
    ) -> Result<Response<CreateCustomerManagedKeyResponse>, Status> {
        key_management::create_customer_managed_key(request).await
    }

    async fn get_managed_key(
        &self,
        request: Request<GetManagedKeyRequest>,
    ) -> Result<Response<GetManagedKeyResponse>, Status> {
        key_management::get_managed_key(request).await
    }

    async fn list_managed_keys(
        &self,
        request: Request<ListManagedKeysRequest>,
    ) -> Result<Response<ListManagedKeysResponse>, Status> {
        key_management::list_managed_keys(request).await
    }

    async fn get_wallet_spending_paths(
        &self,
        request: Request<GetWalletSpendingPathsRequest>,
    ) -> Result<Response<GetWalletSpendingPathsResponse>, Status> {
        wallet_operations::get_wallet_spending_paths(request).await
    }
}
