import os
from functools import cached_property

from aws_cdk import Names, RemovalPolicy, Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct

from kubernetes import commands


class Ec2Cluster(Stack):
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

    @cached_property
    def vpc(self):
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
                "KubeNodePolicy": iam.PolicyDocument(
                    statements=self.NODE_ROLE_POLICY_STATEMENTS
                )
            },
        )

        control_plane_user_data = ec2.UserData.for_linux()

        #        token_command = self.get_token_command(self.secret_name, "us-east-1")

        control_plane_user_data.add_commands(
            *self.BASIC_SETUP,
            "sudo kubeadm config images pull",
            f"TOKEN=$({commands.get_secret_kube_token(self.secret_name)})",
            'sudo kubeadm init --token="$TOKEN" --token-ttl=0 --pod-network-cidr=172.16.0.0/12',
            # Make kubectl useable.
            "mkdir -p $HOME/.kube",
            "cp -i /etc/kubernetes/admin.conf $HOME/.kube/config",
            "chown $(id -u):$(id -g) $HOME/.kube/config",
            f"aws s3 cp /etc/kubernetes/admin.conf s3://{self.bucket_name}/config",
            # Get Vpc CNI config.
            commands.kubectl_apply_github(
                "aws/amazon-vpc-cni-k8s/master/config/master/aws-k8s-cni.yaml"
            ),
            # Enable Kubernetes Dashboard
            commands.kubectl_apply_github(
                "kubernetes/dashboard/v2.5.0/aio/deploy/recommended.yaml"
            ),
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
            "ControlNode",
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

    def get_worker_instance(
        self,
    ) -> ec2.Instance:
        worker_role = iam.Role(
            self,
            "WorkerInstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[],
            inline_policies={
                "KubeNodePolicy": iam.PolicyDocument(
                    statements=self.NODE_ROLE_POLICY_STATEMENTS
                )
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

        return ec2.Instance(
            self,
            "WorkerNode",
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

        # Grant the control instance to the secret and bucket
        bucket.grant_write(control_instance.role)
        secret.grant_read(control_instance.role)

        # Ensure the bucket & secret are created before initializing the control node.
        control_instance.node.add_dependency(secret)
        control_instance.node.add_dependency(bucket)

        worker_instance = self.get_worker_instance()

        bucket.grant_read(worker_instance.role)
        secret.grant_read(worker_instance.role)

        worker_instance.node.add_dependency(control_instance)
