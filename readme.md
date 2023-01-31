# Introduction

Based on Databricks documentation, the basic VPC requirements for a Databricks AWS workspace includes a NAT Gateway with 
access to the internet. However, this is usually a concern with more security-conscious enterprises. 

# Setting Up

1. Copy [`templates/variables_template.tf`](./templates/variables_template.tf) into the root folder as `variables.tf`
1. Update the `variables.tf` with the required information
1. Follow the [terraform setup steps](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/aws-build#prerequisites) to get set up
    1. **Recommended** Set up a new AWS profile on your `aws cli`, so that you can easily isolate your AWS credentials for testing
        1. You can then set your `aws_vars.profile` variable to the profile name
        1. Importantly, set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`


# Running Things
1. To initialize the terraform modules required: `terraform init`
1. To dry-run the build: `terraform plan`
1. To build: `terraform build`
