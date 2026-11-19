#!/bin/bash
# Health check script for localstack to ensure all resources are created

export AWS_ACCESS_KEY_ID=foo
export AWS_SECRET_ACCESS_KEY=bar
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost:4566

echo "Checking LocalStack health..."

# Check if localstack is running
if ! curl -f http://localhost:4566/_localstack/health > /dev/null 2>&1; then
    echo "LocalStack is not running"
    exit 1
fi

echo "LocalStack is running"

# Check if KMS keys are created
echo "Checking KMS keys..."
if ! aws kms list-aliases --endpoint-url=http://localhost:4566 --region us-east-1 2>/dev/null | grep -q 'alias/dev-multi-region-crypto'; then
    echo "KMS keys are not ready"
    exit 1
fi

echo "KMS keys are ready"

# Check if secret is created
echo "Checking Secrets Manager..."
# '00000000-0000-0000-0000-000000000000' is the hardcoded secret name for testing purposes
if ! aws secretsmanager list-secrets --endpoint-url=http://localhost:4566 --region us-east-1 2>/dev/null | grep -q '00000000-0000-0000-0000-000000000000'; then
    echo "Secrets Manager is not ready"
    exit 1
fi

echo "Secrets Manager is ready"

# Verify that the watermark table is active and has deletion protection.
echo "Checking watermark table..."
table_status=$(aws dynamodb describe-table \
    --table-name watermarks \
    --query 'Table.TableStatus' \
    --output text \
    --endpoint-url=http://localhost:4566 \
    --region us-east-1 2>/dev/null)
if [ "${table_status}" != "ACTIVE" ]; then
    echo "Watermark table is not ready"
    exit 1
fi

deletion_protection=$(aws dynamodb describe-table \
    --table-name watermarks \
    --query 'Table.DeletionProtectionEnabled' \
    --output text \
    --endpoint-url=http://localhost:4566 \
    --region us-east-1 2>/dev/null)
if [[ "${deletion_protection}" != [Tt]rue ]]; then
    echo "Watermark table deletion protection is not enabled"
    exit 1
fi

echo "Watermark table is ready"

# Check if replica key exists in us-west-2
echo "Checking replica key in us-west-2..."
if ! aws kms list-aliases --endpoint-url=http://localhost:4566 --region us-west-2 2>/dev/null | grep -q 'alias/dev-multi-region-crypto'; then
    echo "Replica key in us-west-2 is not ready"
    exit 1
fi

echo "All resources are ready!"
exit 0
