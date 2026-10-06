#[cfg(test)]
mod tests {
    use hsm_backend_signing_service::error::AppError;

    #[test]
    fn status_mapping() {
        assert_eq!(AppError::HsmError.status(), 500);
        assert_eq!(AppError::KeyNotFound.status(), 404);
        assert_eq!(AppError::InvalidPayload.status(), 400);
        assert_eq!(AppError::UnsupportedAlgorithm.status(), 400);
    }
}
