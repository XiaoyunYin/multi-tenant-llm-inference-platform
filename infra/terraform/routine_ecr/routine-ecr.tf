# DEC-099 optional R542 boundary fixture; merged only into selected routine roots.
# Arguments match aws_ecr_repository.m5 in the zone module, including force_delete.
variable "ecr_token_actions" { type = list(string) }
variable "ecr_repository_actions" { type = list(string) }
resource "aws_ecr_repository" "descriptive_validation" {
  name                 = "${var.session}-descriptive-ecr"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  encryption_configuration { encryption_type = "AES256" }
  image_scanning_configuration { scan_on_push = true }
  tags = local.tags
}
resource "aws_iam_role_policy" "descriptive_ecr_writer" {
  name = "${var.session}-ecr-writer"
  role = aws_iam_role.task[0].name
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = var.ecr_token_actions, Resource = "*" },
    { Effect = "Allow", Action = var.ecr_repository_actions, Resource = aws_ecr_repository.descriptive_validation.arn }
  ] })
}
resource "aws_iam_role" "descriptive_ecr_pull" {
  name_prefix = "${var.session}-pull-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Principal = { AWS = aws_iam_role.task[0].arn }, Action = "sts:AssumeRole" }
  ] })
  tags = local.tags
}
resource "aws_iam_role_policy_attachment" "descriptive_ecr_pull" {
  role       = aws_iam_role.descriptive_ecr_pull.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly"
}
resource "aws_iam_role_policy" "descriptive_ecr_assume" {
  name = "${var.session}-assume-reader"
  role = aws_iam_role.task[0].name
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "sts:AssumeRole", Resource = aws_iam_role.descriptive_ecr_pull.arn }
  ] })
}
output "descriptive_ecr_validation" {
  value = {
    repository_url  = aws_ecr_repository.descriptive_validation.repository_url
    repository_name = aws_ecr_repository.descriptive_validation.name
    repository_arn  = aws_ecr_repository.descriptive_validation.arn
    writer_role_arn = aws_iam_role.task[0].arn
    writer_policy   = jsondecode(aws_iam_role_policy.descriptive_ecr_writer.policy)
    pull_role_arn   = aws_iam_role.descriptive_ecr_pull.arn
    pull_policy_arn = aws_iam_role_policy_attachment.descriptive_ecr_pull.policy_arn
    settings        = { image_tag_mutability = "IMMUTABLE", encryption_type = "AES256", scan_on_push = true, force_delete = false }
  }
}
