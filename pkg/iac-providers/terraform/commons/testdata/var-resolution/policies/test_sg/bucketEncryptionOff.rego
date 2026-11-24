package accurics

bucketEncryptionOff[retVal] {
    bucket = input.aws_s3_bucket[_]
    bucket.config.encryption_on == false

    retVal := { "Id": bucket.id }
}
