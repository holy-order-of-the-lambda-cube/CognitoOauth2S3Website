output "site-bucket" {
	description = "The S3 bucket containing the secure website"
	value       = aws_s3_bucket.secure-site.bucket
}
