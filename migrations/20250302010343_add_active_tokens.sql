-- Create active_tokens table
CREATE TABLE IF NOT EXISTS active_tokens (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    jti VARCHAR(255) UNIQUE NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_info JSONB,
    CONSTRAINT active_tokens_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

-- Create indexes for active_tokens table
CREATE INDEX IF NOT EXISTS idx_active_tokens_user_id ON active_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_active_tokens_expires_at ON active_tokens(expires_at);

-- Add comment to explain the table
COMMENT ON TABLE active_tokens IS 'Stores information about active JWT tokens for tracking and revocation purposes';
COMMENT ON COLUMN active_tokens.jti IS 'JWT ID - unique identifier for the token';
COMMENT ON COLUMN active_tokens.token_type IS 'Type of token (access or refresh)';
COMMENT ON COLUMN active_tokens.expires_at IS 'When the token will expire';
COMMENT ON COLUMN active_tokens.created_at IS 'When the token was created';
COMMENT ON COLUMN active_tokens.device_info IS 'Optional information about the device that requested the token';