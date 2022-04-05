import os
from functools import cached_property
from json import load

from aws_cdk import Duration, Names, RemovalPolicy, Stack
from aws_cdk import aws_autoscaling as autoscaling
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct

from kubernetes import commands


class K8sCluster(Stack):
    """
    Stack
    """

    BASIC_SETUP = [
        "exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1",
        # Repos
        "sudo curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg",
        'echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list',
        "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg",
        'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list',
        # Packages
        "sudo apt update -y",
        "sudo apt-get install -y awscli jq apt-transport-https ca-certificates curl gnupg lsb-release",
        # Install docker
        "sudo apt-get install -y docker-ce docker-ce-cli containerd.io",
        # Config docker to use systemd cgroups driver
        "sudo sed -i '/^ExecStart/ s/$/ --exec-opt native.cgroupdriver=systemd/' /usr/lib/systemd/system/docker.service",
        "sudo systemctl daemon-reload",
        "sudo systemctl restart docker",
        # Install kube
        "sudo apt-get install -y kubelet kubeadm kubectl",
        "sudo apt-mark hold kubelet kubeadm kubectl",
    ]

    KEY_PAIR_NAME = os.getenv("KEY_PAIR_NAME")

    NODE_ROLE_POLICY_STATEMENTS = [
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ec2:AssignPrivateIpAddresses",
                "ec2:AttachNetworkInterface",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeInstances",
                "ec2:DescribeTags",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeInstanceTypes",
                "ec2:DetachNetworkInterface",
                "ec2:ModifyNetworkInterfaceAttribute",
                "ec2:UnassignPrivateIpAddresses",
            ],
            resources=["*"],
        ),
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["ec2:CreateTags"],
            resources=["arn:aws:ec2:*:*:network-interface/*"],
        ),
        # Allow pulling of image (for CNI).
        iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:GetLifecyclePolicy",
                "ecr:GetLifecyclePolicyPreview",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings",
            ],
            resources=["*"],
        ),
    ]

    with open("kubernetes/policies/alb_controller.json") as policy_file:
        NODE_ALB_CONTROLLER_POLICY = iam.PolicyDocument.from_json(load(policy_file))

    @cached_property
    def vpc(self):
        """
        The VPC
        """
        return ec2.Vpc(
            self,
            "VPC",
            cidr="10.0.0.0/16",
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    cidr_mask=24, name="ingress", subnet_type=ec2.SubnetType.PUBLIC
                )
            ],
        )

    def get_control_instance(self) -> ec2.Instance:

        control_plane_role = iam.Role(
            self,
            "ControlPlaneInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[],
            inline_policies={
                "KubeNode": iam.PolicyDocument(
                    statements=self.NODE_ROLE_POLICY_STATEMENTS
                )
            },
        )

        control_plane_user_data = ec2.UserData.for_linux()

        control_plane_user_data.add_commands(
            *self.BASIC_SETUP,
            "sudo kubeadm config images pull",
            f"TOKEN=$({commands.get_secret_kube_token(self.secret_name)})",
            'sudo kubeadm init --token="$TOKEN" --token-ttl=0 --pod-network-cidr=10.244.0.0/16',
            # Make kubectl useable.
            "mkdir -p $HOME/.kube",
            "cp -i /etc/kubernetes/admin.conf $HOME/.kube/config",
            "chown $(id -u):$(id -g) $HOME/.kube/config",
            # ... and for ubuntu.
            "mkdir /home/ubuntu/.kube",
            "cp /etc/kubernetes/admin.conf /home/ubuntu/.kube/config",
            "chown ubuntu /home/ubuntu/.kube/config",
            # Copy config to s3
            f"aws s3 cp /etc/kubernetes/admin.conf s3://{self.bucket_name}/config",
            # Install helm
            "curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash",
            # Get Vpc CNI config.
            # commands.kubectl_apply_github(
            #    "aws/amazon-vpc-cni-k8s/master/config/master/aws-k8s-cni.yaml"
            # ),
            commands.kubectl_apply_github(
                "flannel-io/flannel/master/Documentation/kube-flannel.yml"
            ),
            # Enable Kubernetes Dashboard
            commands.kubectl_apply_github(
                "kubernetes/dashboard/v2.5.0/aio/deploy/recommended.yaml"
            ),
            # Install k9s
            "curl -L https://github.com/derailed/k9s/releases/download/v0.25.18/k9s_Linux_arm64.tar.gz | tar -xz -C /usr/local/bin/ k9s",
            # Cert manager.
            #       commands.kubectl_apply_github(
            #           "jetstack/cert-manager/releases/download/v1.5.3/cert-manager.yaml",
            #           user_content=False,
            #           validate=False,
            #       ),
            #       # Apply the alb controller, setting --cluster-name from the VPC
            #       commands.kubectl_apply_github(
            #           "kubernetes-sigs/aws-load-balancer-controller/releases/download/v2.4.1/v2_4_1_full.yaml",
            #           user_content=False,
            #           sed=f"s/(--cluster-name=).*/\\1{self.vpc_id}/",
            #       ),
            # Put the discovery file on s3.
            commands.put_kube_config(self.bucket_name),
        )

        control_image = ec2.MachineImage.generic_linux(
            ami_map={
                "us-east-1": "ami-04c5f4bf5cfd49669",
            },
            user_data=control_plane_user_data,
        )

        return ec2.Instance(
            self,
            "Control",
            vpc=self.vpc,
            vpc_subnets=[],
            role=control_plane_role,
            security_group=self.security_group,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass.BURSTABLE4_GRAVITON,
                instance_size=ec2.InstanceSize.SMALL,
            ),
            machine_image=control_image,
            key_name=self.KEY_PAIR_NAME,
        )

    def get_worker_asg(
        self,
    ) -> ec2.Instance:
        worker_role = iam.Role(
            self,
            "WorkerInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[],
            inline_policies={
                "KubeNode": iam.PolicyDocument(
                    statements=self.NODE_ROLE_POLICY_STATEMENTS
                ),
                # The controller runs on the worker nodes, so it needs access to
                # the AWS ALB/NLB resources via IAM permissions
                "KubeALBController": self.NODE_ALB_CONTROLLER_POLICY,
            },
        )

        worker_user_data = ec2.UserData.for_linux()

        worker_user_data.add_commands(
            *self.BASIC_SETUP,
            f"TOKEN=$({commands.get_secret_kube_token(self.secret_name)})",
            f"aws s3 cp s3://{self.bucket_name}/cluster-info.yaml cluster-info.yaml",
            'sudo kubeadm join --token="$TOKEN" --discovery-file=cluster-info.yaml',
        )

        worker_image = ec2.MachineImage.generic_linux(
            ami_map={
                "us-east-1": "ami-04c5f4bf5cfd49669",
            },
            user_data=worker_user_data,
        )

        return autoscaling.AutoScalingGroup(
            self,
            "Worker",
            # Instance Params
            vpc=self.vpc,
            vpc_subnets=[],
            role=worker_role,
            security_group=self.security_group,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass.BURSTABLE4_GRAVITON,
                instance_size=ec2.InstanceSize.SMALL,
            ),
            machine_image=worker_image,
            key_name=self.KEY_PAIR_NAME,
            # Scaling Params
            desired_capacity=1,
        )

    @cached_property
    def security_group(self):
        security_group = ec2.SecurityGroup(
            self, "KubeCluster", vpc=self.vpc, allow_all_outbound=True
        )

        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(22),
            "allow SSH traffic from anywhere",
        )

        security_group.add_ingress_rule(
            security_group,
            ec2.Port.all_traffic(),
            "Allow communication within the cluster",
        )

        return security_group

    @property
    def vpc_id(self) -> str:
        return Names.unique_id(self.vpc)

    @property
    def secret_name(self):
        return f"KubeNodeJoinToken-{self.vpc_id}"

    @property
    def bucket_name(self):
        return f"kube-{self.vpc_id}".lower()

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """
        Kubernetes Cluster Stack
        """
        super().__init__(scope, construct_id, **kwargs)

        # Name the secret based on the VPC
        secret = secretsmanager.Secret(
            self,
            "KubeNodeJoinToken",
            secret_name=self.secret_name,
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_uppercase=True, exclude_punctuation=True, password_length=22
            ),
        )

        # Create a bucket for config
        bucket = s3.Bucket(
            self,
            "KubeConf",
            bucket_name=self.bucket_name,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        control_instance = self.get_control_instance()

        hosted_zone = route53.HostedZone.from_lookup(
            self, "KubeClusterZone", domain_name="kubr.me"
        )

        route53.ARecord(
            self,
            "KubrControl",
            zone=hosted_zone,
            target=route53.RecordTarget.from_ip_addresses(
                control_instance.instance_public_ip
            ),
            record_name="control",
            ttl=Duration.minutes(10),
        )

        # Grant the control instance to the secret and bucket
        bucket.grant_write(control_instance.role)
        secret.grant_read(control_instance.role)

        # Ensure the bucket & secret are created before initializing the control node.
        control_instance.node.add_dependency(secret)
        control_instance.node.add_dependency(bucket)

        worker_group = self.get_worker_asg()

        bucket.grant_read(worker_group.role)
        secret.grant_read(worker_group.role)

        worker_group.node.add_dependency(control_instance)
