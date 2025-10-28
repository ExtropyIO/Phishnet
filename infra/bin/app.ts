#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { TeeAgentsStack } from '../lib/tee-agents-stack';

const app = new cdk.App();

// Let CDK infer account/region from your env/profile
new TeeAgentsStack(app, 'TeeAgentsStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region:  process.env.CDK_DEFAULT_REGION || 'eu-west-1',
  },
});
