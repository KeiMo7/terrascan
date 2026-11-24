module "child" {
  source = "./module"

  # allowed_cidrs is intentionally not passed: the child must combine its
  # own default with the parent-supplied child_encryption argument.
  child_encryption = var.encryption_enabled
}
