terraform {
  required_version = ">= 0.12"
}

#------------------------------------------------------------------------------#
# Common local values
#------------------------------------------------------------------------------#

resource "random_pet" "cluster_name" {}

locals {
  cluster_name = var.cluster_name != null ? var.cluster_name : random_pet.cluster_name.id
  tags         = merge(var.tags, { "terraform-kubeadm:cluster" = local.cluster_name })
}

#------------------------------------------------------------------------------#
# Key pair
#------------------------------------------------------------------------------#

# Performs 'ImportKeyPair' API operation (not 'CreateKeyPair')
resource "aws_key_pair" "main" {
  key_name_prefix = "${local.cluster_name}-"
  public_key      = file(var.public_key_file)
  tags            = local.tags
}

#------------------------------------------------------------------------------#
# Security groups
#------------------------------------------------------------------------------#

# The AWS provider removes the default "allow all "egress rule from all security
# groups, so it has to be defined explicitly.
resource "aws_security_group" "egress" {
  name        = "${local.cluster_name}-egress"
  description = "Allow all outgoing traffic to everywhere"
  vpc_id      = var.vpc_id
  tags        = local.tags
  egress {
    protocol    = -1
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ingress_internal" {
  name        = "${local.cluster_name}-ingress-internal"
  description = "Allow all incoming traffic from nodes and Pods in the cluster"
  vpc_id      = var.vpc_id
  tags        = local.tags
  ingress {
    protocol    = -1
    from_port   = 0
    to_port     = 0
    self        = true
    description = "Allow incoming traffic from cluster nodes"

  }
  ingress {
    protocol    = -1
    from_port   = 0
    to_port     = 0
    cidr_blocks = var.pod_network_cidr_block != null ? [var.pod_network_cidr_block] : null
    description = "Allow incoming traffic from the Pods of the cluster"
  }
}

resource "aws_security_group" "ingress_k8s" {
  name        = "${local.cluster_name}-ingress-k8s"
  description = "Allow incoming Kubernetes API requests (TCP/6443) from outside the cluster"
  vpc_id      = var.vpc_id
  tags        = local.tags
  ingress {
    protocol    = "tcp"
    from_port   = 6443
    to_port     = 6443
    cidr_blocks = var.allowed_k8s_cidr_blocks
  }
  ingress {
    protocol    = "tcp"
    from_port   = 32080
    to_port     = 32080
    cidr_blocks = var.allowed_k8s_cidr_blocks
  }
}
resource "aws_security_group" "ingress_k8s_workers" {
  name        = "${local.cluster_name}-ingress-k8s-workers"
  description = "Allow incoming traffic on port 32080"
  vpc_id      = var.vpc_id
  tags        = local.tags
  ingress {
    protocol    = "tcp"
    from_port   = 32080
    to_port     = 32080
    cidr_blocks = var.allowed_k8s_cidr_blocks
  }
}

resource "aws_security_group" "ingress_ssh" {
  name        = "${local.cluster_name}-ingress-ssh"
  description = "Allow incoming SSH traffic (TCP/22) from outside the cluster"
  vpc_id      = var.vpc_id
  tags        = local.tags
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = var.allowed_ssh_cidr_blocks
  }
}

#------------------------------------------------------------------------------#
# Elastic IP for master node
#------------------------------------------------------------------------------#

# EIP for master node because it must know its public IP during initialisation
resource "aws_eip" "master" {
  domain = "vpc"
  tags   = local.tags
}

resource "aws_eip_association" "master" {
  allocation_id = aws_eip.master.id
  instance_id   = aws_instance.master.id
}

#------------------------------------------------------------------------------#
# Bootstrap token for kubeadm
#------------------------------------------------------------------------------#

# Generate bootstrap token
# See https://kubernetes.io/docs/reference/access-authn-authz/bootstrap-tokens/
resource "random_string" "token_id" {
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "token_secret" {
  length  = 16
  special = false
  upper   = false
}

locals {
  token = "${random_string.token_id.result}.${random_string.token_secret.result}"
}
#------------------------------------------------------------------------------#
# ROLE,POLICIES AND INSTANCE PROFILE
#------------------------------------------------------------------------------#
//iam role
resource "aws_iam_role" "ec2_ecr_access" {
  name = "ec2-ecr-role"

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF
}

//iam role policy
resource "aws_iam_policy" "ecr_access_policy" {
  name   = "ecr_access_policy"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

# Attach the policy to the role
resource "aws_iam_role_policy_attachment" "ecr_access_policy_attachment" {
  policy_arn = aws_iam_policy.ecr_access_policy.arn
  role       = aws_iam_role.ec2_ecr_access.name
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name       = "ec2_profile"
  depends_on = [aws_iam_role_policy_attachment.ecr_access_policy_attachment]
  role       = aws_iam_role.ec2_ecr_access.name
}

#------------------------------------------------------------------------------#
# EC2 instances
#------------------------------------------------------------------------------#

data "aws_ami" "ubuntu" {
  owners      = ["099720109477"] # AWS account ID of Canonical
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }
}

resource "aws_instance" "master" {
  ami                  = data.aws_ami.ubuntu.image_id
  instance_type        = var.master_instance_type
  subnet_id            = var.subnet_id
  key_name             = aws_key_pair.main.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  depends_on           = [aws_iam_instance_profile.ec2_profile]
  vpc_security_group_ids = [
    aws_security_group.egress.id,
    aws_security_group.ingress_internal.id,
    aws_security_group.ingress_k8s.id,
    aws_security_group.ingress_ssh.id
  ]
  tags      = merge(local.tags, { "terraform-kubeadm:node" = "master" })
  user_data = <<-EOF
  #!/bin/bash

  # Install kubeadm and Docker
  
  apt-get install -y apt-transport-https curl
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
  echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" >/etc/apt/sources.list.d/kubernetes.list
  apt-get update
  apt-get install unzip
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  apt-get install -y docker.io kubeadm net-tools

  wget https://github.com/containerd/containerd/releases/download/v1.6.2/containerd-1.6.2-linux-amd64.tar.gz
  tar Czxvf /usr/local containerd-1.6.2-linux-amd64.tar.gz
  wget https://raw.githubusercontent.com/containerd/containerd/main/containerd.service
  mv containerd.service /lib/systemd/system/containerd.service
  systemctl daemon-reload
  systemctl restart containerd.service
  systemctl restart kubelet.service
  systemctl status containerd.service
  systemctl status kubelet.service

  # Run kubeadm
  kubeadm init \
    --token "${local.token}" \
    --token-ttl 15m \
    --apiserver-cert-extra-sans "${aws_eip.master.public_ip}" \
  %{if var.pod_network_cidr_block != null~}
    --pod-network-cidr "${var.pod_network_cidr_block}" \
  %{endif~}
    --node-name master

  # Prepare kubeconfig file for download to local machine
  cp /etc/kubernetes/admin.conf /home/ubuntu
  pwd >/home/ubuntu/out
  whoami >>/home/ubuntu/out
  ls -l /home/ubuntu/admin.conf >>/home/ubuntu/out
  sudo chown ubuntu:ubuntu /home/ubuntu/admin.conf
  ls -l /home/ubuntu/admin.conf >>/home/ubuntu/out
  kubectl --kubeconfig /home/ubuntu/admin.conf config set-cluster kubernetes --server https://${aws_eip.master.public_ip}:6443

  # Indicate completion of bootstrapping on this node
  touch /home/ubuntu/done
  EOF
}

resource "aws_instance" "workers" {
  count                       = var.num_workers
  ami                         = data.aws_ami.ubuntu.image_id
  instance_type               = var.worker_instance_type
  subnet_id                   = var.subnet_id
  associate_public_ip_address = true
  key_name                    = aws_key_pair.main.key_name
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  depends_on                  = [aws_iam_instance_profile.ec2_profile]
  root_block_device {
    volume_size           = 20
    volume_type           = "gp2"
    delete_on_termination = true
  }
  vpc_security_group_ids = [
    aws_security_group.egress.id,
    aws_security_group.ingress_internal.id,
    aws_security_group.ingress_ssh.id,
    aws_security_group.ingress_k8s_workers.id
  ]
  tags      = merge(local.tags, { "terraform-kubeadm:node" = "worker-${count.index}" })
  user_data = <<-EOF
  #!/bin/bash

  # Install kubeadm and Docker
  apt-get install -y apt-transport-https curl
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
  echo "deb https://apt.kubernetes.io/ kubernetes-xenial main" >/etc/apt/sources.list.d/kubernetes.list
  apt-get update
  apt-get install -y docker.io kubeadm net-tools

  wget https://github.com/containerd/containerd/releases/download/v1.6.2/containerd-1.6.2-linux-amd64.tar.gz
  tar Czxvf /usr/local containerd-1.6.2-linux-amd64.tar.gz
  wget https://raw.githubusercontent.com/containerd/containerd/main/containerd.service
  mv containerd.service /lib/systemd/system/containerd.service
  systemctl daemon-reload
  systemctl restart containerd.service
  systemctl restart kubelet.service
  systemctl status containerd.service
  systemctl status kubelet.service

  # Run kubeadm
  kubeadm join ${aws_instance.master.private_ip}:6443 \
    --token ${local.token} \
    --discovery-token-unsafe-skip-ca-verification \
    --node-name worker-${count.index}
  
  apt-get install unzip
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  # Indicate completion of bootstrapping on this node
  touch /home/ubuntu/done
  EOF
}

#------------------------------------------------------------------------------#
# Wait for bootstrap to finish on all nodes
#------------------------------------------------------------------------------#

resource "null_resource" "wait_for_bootstrap_to_finish" {
  provisioner "local-exec" {
    command = <<-EOF
    alias ssh='ssh -q -i ${var.private_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    while true; do
      sleep 2
      ! ssh ubuntu@${aws_eip.master.public_ip} [[ -f /home/ubuntu/done ]] >/dev/null && continue
      %{for worker_public_ip in aws_instance.workers[*].public_ip~}
      ! ssh ubuntu@${worker_public_ip} [[ -f /home/ubuntu/done ]] >/dev/null && continue
      %{endfor~}
      break
    done
    EOF
  }
  triggers = {
    instance_ids = join(",", concat([aws_instance.master.id], aws_instance.workers[*].id))
  }
}

#------------------------------------------------------------------------------#
# Download kubeconfig file from master node to local machine
#------------------------------------------------------------------------------#

locals {
  kubeconfig_file = var.kubeconfig_file != null ? abspath(pathexpand(var.kubeconfig_file)) : "${abspath(pathexpand(var.kubeconfig_dir))}/${local.cluster_name}.conf"
}

resource "null_resource" "download_kubeconfig_file" {
  provisioner "local-exec" {
    command = <<-EOF
    alias scp='scp -q -i ${var.private_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
    scp ubuntu@${aws_eip.master.public_ip}:/home/ubuntu/admin.conf ${local.kubeconfig_file} >/dev/null
    EOF
  }
  triggers = {
    wait_for_bootstrap_to_finish = null_resource.wait_for_bootstrap_to_finish.id
  }
}

resource "null_resource" "calico_apply" {
  provisioner "local-exec" {
    working_dir = path.cwd
    command     = "kubectl --kubeconfig=${local.kubeconfig_file} apply -f calico.yaml && sleep 120"
    interpreter = ["/bin/bash", "-c"]
  }
  depends_on = [null_resource.download_kubeconfig_file]
}
resource "null_resource" "deploy_nginx_controller" {
  provisioner "local-exec" {
    working_dir = "${path.cwd}/ingress-nginx"
    command     = <<-EOF
    kubectl --kubeconfig=${local.kubeconfig_file} create namespace ingress-basic
    helm install --kubeconfig=${local.kubeconfig_file}  ingress-nginx . --namespace ingress-basic --set controller.replicaCount=1
    EOF
    interpreter = ["/bin/bash", "-c"]
  }
  depends_on = [null_resource.calico_apply]
}

# resource "aws_lb_target_group_attachment" "test" {
#   target_group_arn = "<TARGET_GROUP_ARN>"
#   target_id        = aws_instance.master.private_ip
#   port             = 32080
#   depends_on       = [null_resource.deploy_nginx_controller]
# }