#!/bin/bash
# LocalStack runs this script at startup to create the test watermark table.

set -euo pipefail

export AWS_ACCESS_KEY_ID=foo
export AWS_SECRET_ACCESS_KEY=bar
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://${LOCALSTACK_HOST}:${LOCALSTACK_PORT}

table_name="watermarks"

if aws dynamodb describe-table --table-name "${table_name}" > /dev/null 2>&1; then
    echo "Watermark table already exists"
    exit 0
fi

echo "Creating watermark table..."
aws dynamodb create-table \
    --table-name "${table_name}" \
    --attribute-definitions \
        AttributeName=validator_id,AttributeType=S \
        AttributeName=namespace,AttributeType=S \
    --key-schema \
        AttributeName=validator_id,KeyType=HASH \
        AttributeName=namespace,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --deletion-protection-enabled

aws dynamodb wait table-exists --table-name "${table_name}"
echo "Watermark table is ready"
