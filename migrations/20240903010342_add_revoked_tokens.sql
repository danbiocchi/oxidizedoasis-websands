-- Create revoked_tokens table
CREATE TABLE IF NOT EXISTS revoked_tokens (
    id uuid PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    user_id uuid NOT NULL,
    token_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255),
    CONSTRAINT revoked_tokens_user_id_fkey FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);

-- Create indexes for revoked_tokens table
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_jti ON revoked_tokens(jti);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user_id ON revoked_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

-- Add comment to explain the table
COMMENT ON TABLE revoked_tokens IS 'Stores information about revoked JWT tokens for security purposes';
COMMENT ON COLUMN revoked_tokens.jti IS 'JWT ID - unique identifier for the token';
COMMENT ON COLUMN revoked_tokens.token_type IS 'Type of token (access or refresh)';
COMMENT ON COLUMN revoked_tokens.expires_at IS 'When the token would have expired normally';
COMMENT ON COLUMN revoked_tokens.revoked_at IS 'When the token was revoked';
COMMENT ON COLUMN revoked_tokens.reason IS 'Optional reason for revocation (e.g., logout, security concern)';