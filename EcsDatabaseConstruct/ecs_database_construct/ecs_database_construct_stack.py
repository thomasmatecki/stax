from aws_cdk import Stack
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_iam as iam
from constructs import Construct


class EcsDatabaseConstructStack(Stack):
    """
    Stack
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        """
        Stack
        """
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc(
            self,
            "VPC",
            cidr="",
            nat_gateways=0,
            subnet_configuration={
                "name": "public",
                "cidrMask": 24,
                "subnetType": ec2.SubnetType.PUBLIC,
            },
        )

        security_group = ec2.SecurityGroup(self, "SG", vpc=vpc, allow_all_outbound=True)

        security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(),
            ec2.Port.tcp(22),
            "allow SSH traffic from anywhere",
        )

        role = iam.Role(
            self,
            "InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess")
            ],
        )

        ec2_instance = ec2.Instance(
            self,
            "ec2-instance",
            vpc=vpc,
            vpc_subnets=[],
            role=role,
            security_group=security_group,
            instance_type=ec2.InstanceType.of(
                instance_class=ec2.InstanceClass.STANDARD6_GRAVITON,
                instance_size=ec2.InstanceSize.MICRO,
            ),
            machine_image=ec2.AmazonLinux,
            key_name="thomas.matecki@gmail.com",
        )


#  const ec2Instance = new ec2.Instance(this, 'ec2-instance', {
#      vpc,
#      vpcSubnets: {
#        subnetType: ec2.SubnetType.PUBLIC,
#      },
#      role: webserverRole,
#      securityGroup: webserverSG,
#      instanceType: ec2.InstanceType.of(
#        ec2.InstanceClass.T2,
#        ec2.InstanceSize.MICRO,
#      ),
#      machineImage: new ec2.AmazonLinuxImage({
#        generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
#      }),
#      keyName: 'ec2-key-pair',
#    });
#  }


# //            {
# //      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
# //      managedPolicies: [
# //        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3ReadOnlyAccess'),
# //      ],
