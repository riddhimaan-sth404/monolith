use monolith_shared::error::Result;

pub struct LocalGrpcServer {
    listen_address: String,
}

impl LocalGrpcServer {
    pub fn new(address: &str) -> Self {
        Self {
            listen_address: address.to_string(),
        }
    }

    pub async fn start(&self) -> Result<()> {
        tracing::info!("starting local gRPC server on {}", self.listen_address);

        // This server runs on localhost and accepts connections from the Go scanner.
        // It handles:
        // - Scan commands from agent to scanner
        // - Scan results from scanner to agent
        // - Scanner health checks

        // TODO: Start tonic gRPC server
        // Server::builder()
        //     .add_service(ScannerServiceServer::new(service))
        //     .serve(addr)
        //     .await?;

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("stopping local gRPC server");
        Ok(())
    }
}
