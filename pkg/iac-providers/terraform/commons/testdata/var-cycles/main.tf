variable "a" {
  type    = string
  default = "prefix-${var.b}"
}

variable "b" {
  type    = string
  default = "${var.a}-suffix"
}

resource "null_resource" "cyclic" {
  triggers = {
    from_a = var.a
    from_b = var.b
  }
}
