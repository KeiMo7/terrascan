variable "cidrs" {
  description = "CIDR blocks allowed inbound"
  type        = list(string)
}

variable "encryption_enabled" {
  description = "whether bucket encryption is on"
  type        = bool
}

variable "instance_count" {
  description = "number of instances"
  type        = number
  default     = 1
}

variable "tags" {
  type = map(string)
}

variable "secret_token" {
  type      = string
  sensitive = true
}

resource "aws_security_group" "open" {
  name = "open-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.cidrs
  }
}

resource "aws_s3_bucket" "store" {
  bucket = "test-bucket"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  encryption_on = var.encryption_enabled
  count_value   = var.instance_count
  tags          = var.tags
  token         = var.secret_token
}
