# Function to read environment variables from .env file
function Get-EnvVariables {
    $envVars = @{}
    Get-Content .env | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            # Remove quotes if present
            $value = $value -replace '^["'']|["'']$'
            $envVars[$key] = $value
        }
    }
    return $envVars
}

# Function to check if PostgreSQL is installed
function Test-PostgreSQL {
    try {
        $null = Get-Command psql -ErrorAction Stop
        return $true
    }
    catch {
        Write-Host "PostgreSQL is not installed or not in PATH. Please install PostgreSQL and add it to your PATH." -ForegroundColor Red
        exit 1
    }
}

# Function to check if database exists
function Test-DatabaseExists {
    param (
        [string]$dbName,
        [string]$user,
        [string]$password,
        [string]$hostName
    )
    
    $env:PGPASSWORD = $password
    try {
        $result = psql -U $user -h $hostName -d postgres -t -c "SELECT 1 FROM pg_database WHERE datname='$dbName'"
        return $result -and $result.Trim() -eq "1"
    }
    catch {
        Write-Host "Error checking database existence: $_" -ForegroundColor Red
        return $false
    }
    finally {
        $env:PGPASSWORD = ""
    }
}

# Main script
Write-Host "Starting database setup..." -ForegroundColor Cyan

# Check if PostgreSQL is installed
Test-PostgreSQL

# Read environment variables
$envVars = Get-EnvVariables
$dbName = $envVars["DB_NAME"]
$dbHost = $envVars["DB_HOST"]
$appUser = $envVars["DB_USER"]
$appPassword = $envVars["DB_PASSWORD"]
$suUser = $envVars["SU_DB_USER"]
$suPassword = $envVars["SU_DB_PASSWORD"]

if (-not $dbName -or -not $dbHost -or -not $appUser -or -not $appPassword -or -not $suUser -or -not $suPassword) {
    Write-Host "Missing required environment variables in .env file" -ForegroundColor Red
    exit 1
}

Write-Host "Checking if database exists..." -ForegroundColor Cyan
$dbExists = Test-DatabaseExists -dbName $dbName -user $suUser -password $suPassword -hostName $dbHost

if (-not $dbExists) {
    Write-Host "Creating database '$dbName'..." -ForegroundColor Cyan
    $env:PGPASSWORD = $suPassword
    psql -U $suUser -h $dbHost -d postgres -c "CREATE DATABASE $dbName"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to create database" -ForegroundColor Red
        exit 1
    }
}

# Set up permissions
Write-Host "Setting up database permissions..." -ForegroundColor Cyan
$env:PGPASSWORD = $suPassword

# First ensure the public schema exists and set ownership
$schemaSetup = @(
    "CREATE SCHEMA IF NOT EXISTS public",
    "ALTER SCHEMA public OWNER TO $suUser"
)

foreach ($query in $schemaSetup) {
    psql -U $suUser -h $dbHost -d $dbName -c $query
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to set up schema" -ForegroundColor Red
        exit 1
    }
}

# Set up permissions for both users
$permissions = @(
    # Superuser permissions
    "GRANT ALL PRIVILEGES ON DATABASE $dbName TO $suUser",
    "GRANT ALL PRIVILEGES ON SCHEMA public TO $suUser",
    "ALTER DEFAULT PRIVILEGES FOR USER $suUser IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO $suUser",
    "ALTER DEFAULT PRIVILEGES FOR USER $suUser IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO $suUser",
    "ALTER DEFAULT PRIVILEGES FOR USER $suUser IN SCHEMA public GRANT ALL PRIVILEGES ON FUNCTIONS TO $suUser",
    
    # Application user permissions
    "GRANT CONNECT ON DATABASE $dbName TO $appUser",
    "GRANT USAGE, CREATE ON SCHEMA public TO $appUser",
    "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $appUser",
    "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO $appUser",
    "ALTER DEFAULT PRIVILEGES FOR USER $suUser IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO $appUser",
    "ALTER DEFAULT PRIVILEGES FOR USER $suUser IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO $appUser"
)

foreach ($permission in $permissions) {
    psql -U $suUser -h $dbHost -d $dbName -c $permission
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to set permissions: $permission" -ForegroundColor Red
        exit 1
    }
}

# Run migrations
Write-Host "Running database migrations..." -ForegroundColor Cyan

# Set DATABASE_URL for sqlx
$env:DATABASE_URL = "postgres://${suUser}:${suPassword}@${dbHost}/${dbName}"

# Check if sqlx-cli is installed
if (-not (Get-Command sqlx -ErrorAction SilentlyContinue)) {
    Write-Host "Installing sqlx-cli..." -ForegroundColor Cyan
    cargo install sqlx-cli
}

# Run migrations
sqlx migrate run

if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to run migrations" -ForegroundColor Red
    exit 1
}

Write-Host "Database setup completed successfully!" -ForegroundColor Green