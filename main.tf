

#-------------VPC-----------

resource "aws_vpc" "asir_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "asir_vpc"
  }
}

#internet gateway

resource "aws_internet_gateway" "asir_internet_gateway" {
  vpc_id = aws_vpc.asir_vpc.id

  tags = {
    Name = "asir_igw"
  }
}

# Route tables

resource "aws_route_table" "asir_public_rt" {
  vpc_id = aws_vpc.asir_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.asir_internet_gateway.id
  }

  tags = {
    Name = "asir_public"
  }
}

resource "aws_default_route_table" "asir_private_rt" {
  default_route_table_id = aws_vpc.asir_vpc.default_route_table_id

  tags = {
    Name = "asir_private"
  }
}

resource "aws_subnet" "asir_public1_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["public1"]
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "asir_public1"
  }
}

resource "aws_subnet" "asir_public2_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["public2"]
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "asir_public2"
  }
}

resource "aws_subnet" "asir_private1_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["private1"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "asir_private1"
  }
}

resource "aws_subnet" "asir_private2_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["private2"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "asir_private2"
  }
}



resource "aws_subnet" "asir_rds1_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["rds1"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "asir_rds1"
  }
}

resource "aws_subnet" "asir_rds2_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["rds2"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "asir_rds2"
  }
}

resource "aws_subnet" "asir_rds3_subnet" {
  vpc_id                  = aws_vpc.asir_vpc.id
  cidr_block              = var.cidrs["rds3"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[2]

  tags = {
    Name = "asir_rds3"
  }
}

# Asociaciones de subredes y rutas

resource "aws_route_table_association" "asir_public_assoc" {
  subnet_id      = aws_subnet.asir_public1_subnet.id
  route_table_id = aws_route_table.asir_public_rt.id
}

resource "aws_route_table_association" "asir_public2_assoc" {
  subnet_id      = aws_subnet.asir_public2_subnet.id
  route_table_id = aws_route_table.asir_public_rt.id
}

resource "aws_route_table_association" "asir_private1_assoc" {
  subnet_id      = aws_subnet.asir_private1_subnet.id
  route_table_id = aws_default_route_table.asir_private_rt.id
}

resource "aws_route_table_association" "asir_private2_assoc" {
  subnet_id      = aws_subnet.asir_private2_subnet.id
  route_table_id = aws_default_route_table.asir_private_rt.id
}

resource "aws_db_subnet_group" "asir_rds_subnetgroup" {
  name = "asir_rds_subnetgroup"

  subnet_ids = [aws_subnet.asir_rds1_subnet.id,
    aws_subnet.asir_rds2_subnet.id,
    aws_subnet.asir_rds3_subnet.id
  ]

  tags = {
    Name = "asir_rds_sng"
  }
}

#Security groups

resource "aws_security_group" "asir_bastion_sg" {
  name        = "asir_bastion_sg"
  description = "Used for access to the dev instance"
  vpc_id      = aws_vpc.asir_vpc.id


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.localip]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.localip]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#Security group Publico

resource "aws_security_group" "asir_public_sg" {
  name        = "asir_public_sg"
  description = "Used for public and private instances for load balancer access"
  vpc_id      = aws_vpc.asir_vpc.id



  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#Security Group Privado 

resource "aws_security_group" "asir_private_sg" {
  name        = "asir_private_sg"
  description = "Used for private instances"
  vpc_id      = aws_vpc.asir_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#Security Group BBDD

resource "aws_security_group" "asir_rds_sg" {
  name        = "asir_rds_sg"
  description = "Used for DB instances"
  vpc_id      = aws_vpc.asir_vpc.id

  ingress {
    from_port = 3306
    to_port   = 3306
    protocol  = "tcp"

    security_groups = [aws_security_group.asir_bastion_sg.id,
      aws_security_group.asir_public_sg.id,
      aws_security_group.asir_private_sg.id
    ]
  }
}



#---------Instancias-----------

resource "aws_db_instance" "asir_db" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = "5.7.24"
  instance_class         = var.db_instance_class
  name                   = var.dbname
  username               = var.dbuser
  password               = var.dbpassword
  db_subnet_group_name   = aws_db_subnet_group.asir_rds_subnetgroup.name
  vpc_security_group_ids = [aws_security_group.asir_rds_sg.id]
  skip_final_snapshot    = true

  provisioner "local-exec" {
    command = <<EOD
cat <<EOF > group_vars/webservers.yml
dbhost: "${aws_db_instance.asir_db.endpoint}"
dbname: "${var.dbname}"
dbuser: "${var.dbuser}"
dbpasswd: "${var.dbpassword}"
s3code: "${aws_s3_bucket.code.bucket}"
EOF
EOD
  }


}

#key pair

resource "aws_key_pair" "asir_auth" {
  key_name   = var.key_name
  public_key = file(var.public_key_path)
}

#Bastion server

resource "aws_instance" "asir_bastion" {
  instance_type = var.bast_instance_type
  ami           = var.bast_ami

  tags = {
    Name = "asir_bastion"
  }

  key_name               = aws_key_pair.asir_auth.id
  vpc_security_group_ids = [aws_security_group.asir_bastion_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.s3_access_profile.id
  subnet_id              = aws_subnet.asir_public1_subnet.id

  provisioner "local-exec" {
    command = <<EOD
cat <<EOF > aws_hosts 
[webservers] 
${aws_instance.asir_bastion.public_ip} ansible_user=ubuntu
EOF
EOD
  }

  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${aws_instance.asir_bastion.id} --profile obiwan && aws rds wait db-instance-available --db-instance-identifier ${aws_db_instance.asir_db.id} && ansible-playbook -i aws_hosts -b wordpress.yml"
  }
}

#Balanceador

resource "aws_elb" "asir_elb" {
  name = "${var.project}-elb"

  subnets = [aws_subnet.asir_public1_subnet.id,
    aws_subnet.asir_public2_subnet.id
  ]

  security_groups = [aws_security_group.asir_public_sg.id]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = var.elb_healthy_threshold
    unhealthy_threshold = var.elb_unhealthy_threshold
    timeout             = var.elb_timeout
    target              = "TCP:80"
    interval            = var.elb_interval
  }

  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400

  tags = {
    Name = "wp_${var.project}-elb"
  }
}

#AMI 

resource "random_id" "golden_ami" {
  byte_length = 8
}

resource "aws_ami_from_instance" "asir_golden" {
  name               = "asir_ami-${random_id.golden_ami.b64}"
  source_instance_id = aws_instance.asir_bastion.id

}

#launch configuration

resource "aws_launch_configuration" "asir_lc" {
  name_prefix          = "asir_lc-"
  image_id             = aws_ami_from_instance.asir_golden.id
  instance_type        = var.lc_instance_type
  security_groups      = [aws_security_group.asir_private_sg.id]
  iam_instance_profile = aws_iam_instance_profile.s3_access_profile.id
  key_name             = aws_key_pair.asir_auth.id
  #user_data            = file("userdata")

  lifecycle {
    create_before_destroy = true
  }
}

#ASG 


resource "aws_autoscaling_group" "asir_asg" {
  name                      = "asg-${aws_launch_configuration.asir_lc.id}"
  max_size                  = var.asg_max
  min_size                  = var.asg_min
  health_check_grace_period = var.asg_grace
  health_check_type         = var.asg_hct
  #desired_capacity          = var.asg_cap
  force_delete              = true
  load_balancers            = [aws_elb.asir_elb.id]

  vpc_zone_identifier = [aws_subnet.asir_private1_subnet.id,
    aws_subnet.asir_private2_subnet.id
  ]

  launch_configuration = aws_launch_configuration.asir_lc.name

  tag {
    key                 = "Name"
    value               = "asir_asg-instance"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_policy" "asg_high" {
  name                   = "asg-high-policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asir_asg.name
}

resource "aws_cloudwatch_metric_alarm" "asg_high" {
  alarm_name          = "asg-high-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "70"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asir_asg.name
  }

  alarm_description = "Esta metrica monitoriza el uso alto de CPU en EC2"
  alarm_actions     = [aws_autoscaling_policy.asg_high.arn]
}
##---------------------------------------------------------------------------

resource "aws_autoscaling_policy" "asg_low" {
  name                   = "asg-low-policy"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.asir_asg.name
}

resource "aws_cloudwatch_metric_alarm" "asg_low" {
  alarm_name          = "asg-low-alarm"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "40"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.asir_asg.name
  }

  alarm_description = "Esta metrica monitoriza el uso bajo de CPU en EC2"
  alarm_actions     = [aws_autoscaling_policy.asg_low.arn]
}






#------------S3---------------- 

#Acceso s3

resource "aws_iam_role" "s3_rol_acceso" {
  name = "s3_rol_acceso"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
  {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
  },
      "Effect": "Allow",
      "Sid": ""
      }
    ]
}
EOF
}

resource "aws_iam_instance_profile" "s3_access_profile" {
  name = "s3_access"
  role = aws_iam_role.s3_rol_acceso.name
}

resource "aws_iam_role_policy" "s3_access_policy" {
  name = "s3_access_policy"
  role = aws_iam_role.s3_rol_acceso.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
EOF
}

#S3 endpoint

resource "aws_vpc_endpoint" "asir_private-s3_endpoint" {
  vpc_id       = aws_vpc.asir_vpc.id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  route_table_ids = [aws_vpc.asir_vpc.main_route_table_id,
    aws_route_table.asir_public_rt.id,
  ]

  policy = <<POLICY
{
    "Statement": [
        {
            "Action": "*",
            "Effect": "Allow",
            "Resource": "*",
            "Principal": "*"
        }
    ]
}
POLICY
}

#S3 code bucket


resource "aws_s3_bucket" "code" {
  bucket        = "${var.project}-aroa-code"
  acl           = "private"
  force_destroy = true

  tags = {
    Name = "code bucket"
  }
}


#-------OUTPUTS ------------

output "Database_Name" {
  value = var.dbname
}

output "Database_Hostname" {
  value = aws_db_instance.asir_db.endpoint
}

output "Database_Username" {
  value = var.dbuser
}

output "Database_Password" {
  value = var.dbpassword
}
output "Wordpress_Address" {
  value = "http://${aws_instance.asir_bastion.public_ip}"
}

output "balanceador" {
  value = aws_elb.asir_elb.dns_name
}

