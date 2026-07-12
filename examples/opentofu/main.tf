terraform {
  required_version = ">= 1.9.0"

  backend "s3" {
    bucket                      = "example-encrypted-state"
    key                         = "production/terraform.tfstate"
    region                      = "us-east-1"
    endpoints                   = { s3 = "https://s3.example.invalid" }
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
  }
}

# State/plan encryption is configured exclusively through TF_ENCRYPTION.
# Backend credentials are supplied as AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY.
# Never pass credentials via -backend-config command-line arguments.
