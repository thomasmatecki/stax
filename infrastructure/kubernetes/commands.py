def kubectl_apply_github(path):
    return f"kubectl apply -f https://raw.githubusercontent.com/{path}"


def put_kube_config(bucket_name: str):
    return " | ".join(
        [
            "kubectl -n kube-public get cm cluster-info -o yaml",
            'grep "kubeconfig:" -A11',
            'grep "apiVersion" -A10',
            'sed "s/    //"',
            f"aws s3 cp - s3://{bucket_name}/cluster-info.yaml",
        ]
    )


def get_secret_kube_token(secret_name: str, region="us-east-1"):
    return " | ".join(
        [
            f"aws secretsmanager get-secret-value --secret-id {secret_name} --region={region}",
            """jq -r '(.SecretString[0:6] + "." + .SecretString[6:])'""",
        ]
    )
