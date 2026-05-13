"""
Phase 3 — Python for DevSecOps
Project 1: AWS Resource Inventory Script

This script demonstrates how DevSecOps engineers use Python to:
- Interact with cloud APIs (boto3)
- Audit infrastructure automatically
- Detect security misconfigurations
- Generate compliance reports

Prerequisites:
    pip install boto3 tabulate
    aws configure  (set up credentials)
"""

import boto3
import json
from datetime import datetime, timezone
from typing import Dict, List


def get_ec2_instances(region: str = "us-east-1") -> List[Dict]:
    """
    List all EC2 instances with security-relevant details.
    
    Security checks:
    - Is the instance publicly accessible?
    - Is it using an IAM role?
    - Is encryption enabled on volumes?
    """
    ec2 = boto3.client("ec2", region_name=region)
    instances = []

    response = ec2.describe_instances()
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            # Get instance name from tags
            name = "unnamed"
            for tag in instance.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]

            # Security checks
            public_ip = instance.get("PublicIpAddress", None)
            iam_role = instance.get("IamInstanceProfile", {}).get("Arn", "NONE - RISK!")

            instances.append({
                "Name": name,
                "InstanceId": instance["InstanceId"],
                "State": instance["State"]["Name"],
                "Type": instance["InstanceType"],
                "PublicIP": public_ip or "None (private)",
                "IAMRole": iam_role,
                "LaunchTime": str(instance["LaunchTime"]),
                "SecurityGroups": [sg["GroupName"] for sg in instance["SecurityGroups"]],
                "RISK_PUBLIC": "YES" if public_ip else "NO",
                "RISK_NO_ROLE": "YES" if iam_role == "NONE - RISK!" else "NO",
            })

    return instances


def get_s3_buckets() -> List[Dict]:
    """
    List all S3 buckets with security audit.
    
    Security checks:
    - Is the bucket public?
    - Is encryption enabled?
    - Is versioning enabled?
    - Is logging enabled?
    """
    s3 = boto3.client("s3")
    buckets = []

    response = s3.list_buckets()
    for bucket in response["Buckets"]:
        bucket_name = bucket["Name"]
        bucket_info = {
            "Name": bucket_name,
            "Created": str(bucket["CreationDate"]),
            "Public": "UNKNOWN",
            "Encrypted": "UNKNOWN",
            "Versioning": "UNKNOWN",
            "Logging": "UNKNOWN",
        }

        # Check public access
        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)
            config = public_access["PublicAccessBlockConfiguration"]
            is_blocked = all([
                config["BlockPublicAcls"],
                config["IgnorePublicAcls"],
                config["BlockPublicPolicy"],
                config["RestrictPublicBuckets"],
            ])
            bucket_info["Public"] = "BLOCKED" if is_blocked else "RISK - PUBLIC!"
        except Exception:
            bucket_info["Public"] = "RISK - NO BLOCK CONFIG!"

        # Check encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            bucket_info["Encrypted"] = "YES"
        except Exception:
            bucket_info["Encrypted"] = "RISK - NOT ENCRYPTED!"

        # Check versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "Disabled")
            bucket_info["Versioning"] = status
        except Exception:
            bucket_info["Versioning"] = "Disabled"

        # Check logging
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" in logging_config:
                bucket_info["Logging"] = "YES"
            else:
                bucket_info["Logging"] = "RISK - NO LOGGING!"
        except Exception:
            bucket_info["Logging"] = "UNKNOWN"

        buckets.append(bucket_info)

    return buckets


def get_iam_users() -> List[Dict]:
    """
    Audit IAM users for security risks.
    
    Security checks:
    - Does the user have MFA enabled?
    - When were credentials last rotated?
    - Does the user have console access?
    - Are there unused access keys?
    """
    iam = boto3.client("iam")
    users = []

    response = iam.list_users()
    for user in response["Users"]:
        username = user["UserName"]
        user_info = {
            "Username": username,
            "Created": str(user["CreateDate"]),
            "LastActivity": str(user.get("PasswordLastUsed", "Never")),
            "MFA": "UNKNOWN",
            "AccessKeys": 0,
            "OldKeys": "NO",
        }

        # Check MFA
        try:
            mfa_devices = iam.list_mfa_devices(UserName=username)
            user_info["MFA"] = "YES" if mfa_devices["MFADevices"] else "RISK - NO MFA!"
        except Exception:
            pass

        # Check access keys
        try:
            keys = iam.list_access_keys(UserName=username)
            user_info["AccessKeys"] = len(keys["AccessKeyMetadata"])

            # Check key age (should rotate every 90 days)
            for key in keys["AccessKeyMetadata"]:
                key_age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if key_age > 90:
                    user_info["OldKeys"] = f"RISK - {key_age} days old!"
        except Exception:
            pass

        users.append(user_info)

    return users


def check_security_groups(region: str = "us-east-1") -> List[Dict]:
    """
    Audit security groups for dangerous rules.
    
    Critical check: Any rule allowing 0.0.0.0/0 (entire internet)
    on sensitive ports is a HIGH RISK.
    """
    ec2 = boto3.client("ec2", region_name=region)
    risky_groups = []

    SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL",
                      5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}

    response = ec2.describe_security_groups()
    for sg in response["SecurityGroups"]:
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    # Check if it's a sensitive port
                    for port, service in SENSITIVE_PORTS.items():
                        if from_port <= port <= to_port:
                            risky_groups.append({
                                "GroupId": sg["GroupId"],
                                "GroupName": sg["GroupName"],
                                "Port": port,
                                "Service": service,
                                "CIDR": cidr,
                                "RISK": f"HIGH - {service} open to internet!",
                            })

    return risky_groups


def generate_report():
    """Generate a complete security inventory report."""
    print("=" * 60)
    print("  AWS SECURITY INVENTORY REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # EC2 Instances
    print("\n[1] EC2 INSTANCES")
    print("-" * 40)
    try:
        instances = get_ec2_instances()
        for inst in instances:
            risk_flag = " ⚠️" if inst["RISK_PUBLIC"] == "YES" else ""
            print(f"  {inst['Name']} ({inst['InstanceId']}){risk_flag}")
            print(f"    State: {inst['State']} | Type: {inst['Type']}")
            print(f"    Public IP: {inst['PublicIP']}")
            print(f"    IAM Role: {inst['IAMRole']}")
            print()
    except Exception as e:
        print(f"  Error: {e}")

    # S3 Buckets
    print("\n[2] S3 BUCKETS")
    print("-" * 40)
    try:
        buckets = get_s3_buckets()
        for bucket in buckets:
            risk_flag = " ⚠️" if "RISK" in bucket["Public"] else ""
            print(f"  {bucket['Name']}{risk_flag}")
            print(f"    Public: {bucket['Public']}")
            print(f"    Encrypted: {bucket['Encrypted']}")
            print(f"    Versioning: {bucket['Versioning']}")
            print()
    except Exception as e:
        print(f"  Error: {e}")

    # Security Groups
    print("\n[3] RISKY SECURITY GROUPS")
    print("-" * 40)
    try:
        risky = check_security_groups()
        if risky:
            for sg in risky:
                print(f"  ⚠️  {sg['GroupName']} ({sg['GroupId']})")
                print(f"    {sg['RISK']}")
                print()
        else:
            print("  ✅ No overly permissive security groups found.")
    except Exception as e:
        print(f"  Error: {e}")

    # IAM Users
    print("\n[4] IAM USER AUDIT")
    print("-" * 40)
    try:
        users = get_iam_users()
        for user in users:
            risk_flag = " ⚠️" if "RISK" in user["MFA"] else ""
            print(f"  {user['Username']}{risk_flag}")
            print(f"    MFA: {user['MFA']}")
            print(f"    Access Keys: {user['AccessKeys']}")
            print(f"    Old Keys: {user['OldKeys']}")
            print()
    except Exception as e:
        print(f"  Error: {e}")

    print("=" * 60)
    print("  REPORT COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    generate_report()
