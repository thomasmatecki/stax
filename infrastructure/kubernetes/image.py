from aws_cdk import Stack
from aws_cdk import aws_cloudformation as cloudformation
from aws_cdk import aws_ec2 as ec2
from constructs import Construct


class K8sImage(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """
        Kubernetes Cluster Stack
        """
        super().__init__(scope, construct_id, **kwargs)

        control_image = ec2.MachineImage.generic_linux(
            ami_map={
                "us-east-1": "ami-04c5f4bf5cfd49669",
            },
        )

        init = (
            ec2.CloudFormationInit.from_config_sets(
                config_sets={
                    # Applies the configs below in this order
                    "default": ["yumPreinstall", "config"]
                },
                configs={
                    "apt_preinstall": ec2.InitConfig(
                        [
                            ec2.InitCommand.argv_command(
                                [
                                    "curl",
                                    "-fsSLo",
                                    "/usr/share/keyrings/kubernetes-archive-keyring.gpg",
                                    "https://packages.cloud.google.com/apt/doc/apt-key.gpg",
                                ]
                            ),
                            ec2.InitCommand.shell_command(
                                'echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list'
                            ),
                            ec2.InitCommand.shell_command(
                                "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg"
                            ),
                            ec2.InitCommand.shell_command(
                                'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list',
                            ),
                            ## Packages
                            ec2.InitCommand.argv_command(["apt", "update", "-y"]),
                            #    ec2.InitCommand.argv_command(
                            #        [
                            #            "apt-get",
                            #            "install",
                            #            "-y",
                            #        ]
                            #    ),
                            ec2.InitCommand.argv_command(
                                [
                                    "sed",
                                    "-i",
                                    "/^ExecStart/ s/$/ --exec-opt native.cgroupdriver=systemd/",
                                    "/usr/lib/systemd/system/docker.service",
                                ]
                            ),
                            ec2.InitCommand.shell_command(
                                "systemctl daemon-reload",
                            ),
                            ec2.InitCommand.shell_command(
                                "sudo systemctl restart docker",
                            )
                            ## Install kube
                            # "sudo apt-get install -y kubelet kubeadm kubectl",
                            # "sudo apt-mark hold kubelet kubeadm kubectl",
                        ]
                    ),
                    #                    "yum_preinstall": ec2.InitConfig(
                    #                        [
                    #                    ),
                    "config": ec2.InitConfig(
                        [
                            # Create a JSON file from tokens (can also create other files)
                            ec2.InitFile.from_object(
                                "/etc/stack.json",
                                {
                                    "stack_id": Stack.of(self).stack_id,
                                    "stack_name": Stack.of(self).stack_name,
                                    "region": Stack.of(self).region,
                                },
                            ),
                            # Create a group and user
                            ec2.InitGroup.from_name("my-group"),
                            ec2.InitUser.from_name("my-user"),
                            # Install an RPM from the internet
                            ec2.InitPackage.rpm(
                                "http://mirrors.ukfast.co.uk/sites/dl.fedoraproject.org/pub/epel/8/Everything/x86_64/Packages/r/rubygem-git-1.5.0-2.el8.noarch.rpm"
                            ),
                        ]
                    ),
                },
            ),
        )

        return ec2.Instance(
            self,
            "Control",
            vpc=self.vpc,
            vpc_subnets=[],
            init=init,
            security_group=self.security_group,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass.BURSTABLE4_GRAVITON,
                instance_size=ec2.InstanceSize.SMALL,
            ),
            machine_image=control_image,
            key_name=self.KEY_PAIR_NAME,
        )
