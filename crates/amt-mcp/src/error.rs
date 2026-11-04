use rmcp::model::{ErrorCode, ErrorData};

/// Maps a tool failure onto an MCP error. Bad input (a malformed consent code,
/// an unknown escape) is INVALID_PARAMS; everything else is internal.
pub fn tool_error(e: anyhow::Error) -> ErrorData {
    if let Some(err) = e.downcast_ref::<amt::Error>() {
        let code = match err {
            amt::Error::InvalidArgument(_) => ErrorCode::INVALID_PARAMS,
            _ => ErrorCode::INTERNAL_ERROR,
        };
        return ErrorData::new(code, err.to_string(), None);
    }
    ErrorData::new(ErrorCode::INTERNAL_ERROR, e.to_string(), None)
}
