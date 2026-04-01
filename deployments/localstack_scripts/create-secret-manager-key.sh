#!/bin/bash
# Script run by localstack at startup to create kms keys for testing

export AWS_ACCESS_KEY_ID=foo
export AWS_SECRET_ACCESS_KEY=bar
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://${LOCALSTACK_HOST}:${LOCALSTACK_PORT}

echo "Creating secret for testing"
aws secretsmanager create-secret --name "00000000-0000-0000-0000-000000000000"
echo "Secret created"
