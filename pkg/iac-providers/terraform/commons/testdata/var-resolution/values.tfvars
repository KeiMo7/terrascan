cidrs              = ["0.0.0.0/0"]
encryption_enabled = true
instance_count     = 3
tags = {
  env = "prod"
}
secret_token = "from-hcl-tfvars"
