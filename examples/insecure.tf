resource "aws_s3_bucket" "logs" {
  bucket = "my-company-logs"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier          = "customers-db"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  storage_encrypted   = false
  publicly_accessible = true
}