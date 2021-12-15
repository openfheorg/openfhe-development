# Setup GitHub Actions Runner

### Launch an EC2 Instance using AWS CLI

```
aws ec2 run-instances \
    --image-id <AMI-Id> \
    --count 1 \
    --instance-type <EC2-Type> \
    --key-name <Key-Pair-Name> \
    --subnet-id <Subnet> \
    --security-group-ids <Security-Group-ID>
    --user-data file://user-data.txt
```

This will create an EC2 instance.


### Configure the EC2 Instance as GitHub Actions Runner

Refer this documentation on how to self-hosted runner to a repository:
https://docs.github.com/en/actions/hosting-your-own-runners/adding-self-hosted-runners