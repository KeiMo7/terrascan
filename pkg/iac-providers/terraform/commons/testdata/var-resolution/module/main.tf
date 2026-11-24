variable "allowed_cidrs" {
  type    = list(string)
  default = ["10.0.0.0/8"]
}

variable "child_encryption" {
  type = bool
}

resource "aws_security_group" "child_sg" {
  name = "child-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
}

resource "aws_s3_bucket" "child_bucket" {
  bucket        = "child-bucket"
  encryption_on = var.child_encryption
}
