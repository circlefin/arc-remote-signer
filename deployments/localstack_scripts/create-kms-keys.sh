#!/bin/bash
# Script run by localstack at startup to create kms keys for testing

export AWS_ACCESS_KEY_ID=foo
export AWS_SECRET_ACCESS_KEY=bar
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://${LOCALSTACK_HOST}:${LOCALSTACK_PORT}

echo "Creating multi-region primary KMS key..."
key_id=$(aws kms create-key \
  --multi-region \
  --description "Multi-Region Primary Key for dev environment" \
  --output=text \
  --query "KeyMetadata.KeyId")

echo "Creating alias for the multi-region key..."
aws kms create-alias \
  --alias-name alias/dev-multi-region-crypto \
  --target-key-id $key_id

echo "Creating replica key in us-west-2 region..."
aws kms replicate-key \
  --key-id $key_id \
  --region us-east-1 \
  --replica-region us-west-2 \
  --output=text \
  --query "KeyMetadata.KeyId"

echo "Creating alias for the replica key in us-west-2..."
aws kms create-alias \
  --region us-west-2 \
  --alias-name alias/dev-multi-region-crypto \
  --target-key-id $key_id

echo "Verifying multi-region configuration..."
aws kms describe-key --key-id $key_id
echo "Success! Multi-region KMS keys have been created:"
echo "Alias: alias/dev-multi-region-crypto"
