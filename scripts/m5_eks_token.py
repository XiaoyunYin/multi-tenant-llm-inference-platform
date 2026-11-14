"""kubectl exec credential using the locked boto3, not an uninstalled AWS CLI.

AWS EKS IAM token format: SigV4 STS GetCallerIdentity, x-k8s-aws-id signed.
https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html
"""

import base64
import datetime
import json
import sys


def token(session, cluster):
    from botocore.signers import RequestSigner

    sts = session.client("sts", region_name="us-east-1")
    signer = RequestSigner(
        sts.meta.service_model.service_id,
        "us-east-1",
        "sts",
        "v4",
        session.get_credentials(),
        session.events,
    )
    url = signer.generate_presigned_url(
        {
            "method": "GET",
            "url": "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
            "body": {},
            "headers": {"x-k8s-aws-id": cluster},
            "context": {},
        },
        region_name="us-east-1",
        expires_in=60,
        operation_name="",
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


if __name__ == "__main__":
    import boto3

    print(
        json.dumps(
            {
                "apiVersion": "client.authentication.k8s.io/v1",
                "kind": "ExecCredential",
                "status": {
                    "expirationTimestamp": (
                        datetime.datetime.now(datetime.UTC)
                        + datetime.timedelta(minutes=14)
                    )
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "token": token(boto3.Session(region_name="us-east-1"), sys.argv[1]),
                },
            }
        )
    )
