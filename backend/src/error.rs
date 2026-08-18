use monolith_shared::error::EdrError;

pub type ServiceResult<T> = Result<T, EdrError>;
