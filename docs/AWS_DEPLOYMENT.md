# Deploying to real AWS (optional)

Costs money: Aurora, KMS and Config all bill. Use a personal account, finish quickly, then delete the stack.

## 1. Deploy the stack
Console: CloudFormation > Create stack > upload `infra/template.yaml`.
Enter your VpcId and two SubnetIds in different Availability Zones. Leave the rest as default.
If AWS Config already records in your region, set CreateConfigRecorder to `false`.
If a Config rule fails with "no configuration recorder", wait a minute and retry the stack.

CLI alternative:
```
aws cloudformation deploy --template-file infra/template.yaml --stack-name medivault \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides VpcId=vpc-xxxx SubnetIds=subnet-aaa,subnet-bbb
```

## 2. Configure the app
Install extras: `pip install -r requirements-aws.txt`

Set values from the stack Outputs (Windows PowerShell shown; use `export` on Mac/Linux):
```
$env:MEDIVAULT_MODE="aws"
$env:AWS_REGION="ap-south-1"
$env:MEDIVAULT_KMS_KEY_ID="<KmsKeyId>"
$env:MEDIVAULT_S3_BUCKET="<DataBucketName>"
$env:MEDIVAULT_DB_HOST="<AuroraEndpoint>"
$env:MEDIVAULT_DB_SECRET_ARN="<AuroraSecretArn>"
$env:MEDIVAULT_CONFIG_PREFIX="medivault-"
```
Credentials come from `aws configure` or an IAM role. The identity needs the permissions in the `medivault-app` role.
Your machine must be able to reach Aurora (the template keeps it private: run the app on EC2 in the VPC, or use a VPN/bastion).

## 3. Run
`python app.py`. On first start the app creates tables and seeds the demo users and synthetic patients in Aurora.

## 4. Clean up
Delete the CloudFormation stack. Empty both S3 buckets first if the delete fails, and the KMS key enters a 7 to 30 day deletion wait.
