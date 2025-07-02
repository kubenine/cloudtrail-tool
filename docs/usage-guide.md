# CloudTrail Intelligence Dashboard - Usage Guide

This guide will help you effectively use the CloudTrail Intelligence Dashboard for AWS security monitoring and analysis.

## 🏠 Dashboard Overview

The dashboard consists of five main tabs, each designed for specific monitoring and analysis tasks:

1. **SSO User Activity** - Monitor AWS SSO user actions
2. **IAM User Activity** - Track traditional IAM user activities  
3. **Natural Language Search** - AI-powered CloudTrail log analysis
4. **Resource Activity** - Monitor AWS service usage
5. **Account Audit** - Comprehensive security and compliance auditing

## 🔍 Natural Language Search

### Basic Usage

The Natural Language Search feature allows you to query CloudTrail logs using plain English:

**Example Queries:**
- "Who created an S3 bucket today?"
- "Show me all EC2 instance changes in the last 6 hours"
- "What security-related changes were made yesterday?"
- "Who accessed the database in the last week?"

### Query Best Practices

1. **Be Specific**: Include timeframes and resource types
   - ✅ "Show EC2 instance terminations in the last 24 hours"
   - ❌ "Show instance changes"

2. **Use Service Names**: Reference AWS services by name
   - ✅ "S3 bucket operations", "Lambda function deployments"
   - ❌ "Storage changes", "Function stuff"

3. **Include Actions**: Specify the type of activity
   - ✅ "IAM role creation and deletion"
   - ❌ "IAM changes"

### Time Window Settings

- Use the sidebar slider to adjust the search time window (1-168 hours)
- Longer time windows may return more results but take longer to process
- For detailed investigations, start with shorter windows and expand as needed

## 👤 User Activity Monitoring

### SSO User Activity

1. Select a user from the dropdown (displays: Name (Email))
2. Click "View Activity" to see their recent actions
3. Review the AI-generated summary for key insights
4. Explore detailed event timeline grouped by date

### IAM User Activity

1. Choose an IAM user from the list
2. View their activity pattern and resource interactions
3. Analyze security-relevant actions and access patterns

## 🏗️ Resource Activity Analysis

### Service Selection

1. Choose from 20+ AWS services in the dropdown
2. Optionally filter by specific resource types
3. View common actions for context
4. Analyze service-specific activity patterns

### Supported Services

- **Compute**: EC2, Lambda, ECS, EKS
- **Storage**: S3, EBS, EFS
- **Database**: RDS, DynamoDB, ElastiCache
- **Networking**: VPC, CloudFront, Route 53
- **Security**: IAM, KMS, Secrets Manager
- **And many more...**

## 🛡️ Account Audit Features

The Account Audit section provides comprehensive security analysis across four main areas:

### Security Overview

**Automated Security Scoring:**
- Real-time security score calculation (0-100)
- Color-coded risk indicators
- Detailed findings with remediation steps

**Key Security Checks:**
- Password policy compliance
- MFA adoption rates (console users only)
- Access key rotation status
- Root account usage monitoring

### User Analysis

#### All Users Overview
- Complete user inventory and metrics
- Security status dashboard
- Export capabilities for compliance reporting

#### Individual User Analysis - NEW! 🆕

**Comprehensive IAM Permission Risk Assessment:**

The dashboard now includes an advanced risk assessment feature that analyzes individual users' IAM permissions and provides:

**🔍 Risk Scoring System:**
- **Risk Levels**: Critical (70-100), High (50-69), Medium (30-49), Low (0-29)
- **Comprehensive Analysis**: Evaluates attached policies, group memberships, and security posture
- **AI-Powered Insights**: Detailed risk analysis using GPT-4 (when OpenAI API key is configured)

**📊 Risk Assessment Components:**

1. **Critical AWS Policies Detection**
   - Identifies high-risk managed policies (AdministratorAccess, PowerUserAccess, etc.)
   - Risk scoring based on policy impact
   - Policy descriptions and recommendations

2. **High-Risk Permission Analysis**
   - Scans for dangerous permissions (iam:*, s3:*, ec2:*, etc.)
   - Groups permissions by policy for easy review
   - Explains potential security impact

3. **Security Profile Evaluation**
   - Console access and MFA status
   - Access key age and rotation needs
   - Group-inherited risks

4. **Unused Permission Detection**
   - Identifies permissions not used in last 90 days
   - Supports principle of least privilege
   - Recommendations for permission cleanup

5. **AI-Powered Risk Analysis** (with OpenAI API key)
   - **Risk Summary**: Overview of main security concerns
   - **Key Vulnerabilities**: Top 3-5 specific security risks
   - **Impact Assessment**: Potential damage if account is compromised
   - **Immediate Actions**: Priority steps to reduce risk
   - **Long-term Recommendations**: Strategic security improvements

**🎯 How to Use Individual User Risk Assessment:**

1. Go to **Account Audit** → **User Analysis** tab
2. Select **Individual User Analysis**
3. Choose a user from the dropdown
4. Wait for comprehensive analysis to complete
5. Review the detailed risk assessment:
   - Check the overall risk score and level
   - Read AI-powered analysis (if available)
   - Review critical policies and high-risk permissions
   - Examine unused permissions for cleanup opportunities
   - Follow immediate recommendations

**📈 Risk Scoring Methodology:**

The risk score is calculated based on:
- **Critical Policies** (AdministratorAccess: +50, PowerUserAccess: +35, IAMFullAccess: +40)
- **High-Risk Permissions** (+10 each for dangerous permissions, +30 for wildcard *)
- **Group Inherited Risks** (+15 for each critical policy from groups)
- **Security Factors** (+20 for console access without MFA, +10 for old access keys)
- **Unused Permissions** (+15 if >10 unused permissions found)

### Permission Analysis - ENHANCED! 🆕

The Permission Analysis tab now includes three analysis modes:

#### 1. Quick Overview
- Basic overprivileged account detection
- Quick security check for immediate issues

#### 2. Comprehensive Risk Assessment - NEW!
**Organization-Wide Risk Analysis:**

- **Overall Security Metrics**
  - Total user count and security score
  - High-risk user identification
  - Security posture percentage

- **Risk Distribution Visualization**
  - Interactive pie chart showing risk levels
  - Detailed percentage breakdown
  - Color-coded risk indicators

- **High-Risk User Dashboard**
  - Prioritized list of users requiring attention
  - Key issues summary for each user
  - Direct links to detailed individual analysis

- **Common Vulnerabilities Report**
  - Most frequent security issues across the organization
  - Percentage of users affected
  - Prioritized remediation guidance

- **Export Capabilities**
  - Comprehensive Excel reports
  - Summary metrics and detailed findings
  - High-risk user lists and vulnerability analysis

#### 3. Permission Changes
- Historical permission modification tracking
- Recent policy attachments and modifications

### Compliance Reports

**Automated Compliance Checking:**
- Password policy validation against best practices
- MFA adoption metrics and non-compliant users
- Access key rotation compliance
- Root account usage monitoring

**Export and Reporting:**
- Excel export functionality
- Compliance summary reports
- Detailed findings documentation

## 📊 Understanding the Data

### Event Information

Each event in the dashboard shows:
- **Timestamp**: When the action occurred (12-hour format)
- **User**: Who performed the action
- **Action**: What was done (AWS API call)
- **Resource**: What was affected
- **Source IP**: Where the action originated
- **Details**: Request parameters and additional context

### Risk Indicators

**Color Coding:**
- 🔴 **Critical/High Risk**: Immediate attention required
- 🟠 **Medium Risk**: Should be reviewed
- 🟡 **Low Risk**: Monitor as needed
- 🟢 **Good**: Follows best practices

## 🔧 Configuration and Settings

### Time Window Configuration

- **Default**: 24 hours
- **Range**: 1-168 hours (1 week maximum)
- **Impact**: Longer windows = more comprehensive data but slower queries

### Token Usage Monitoring

When using AI features:
- Monitor token usage in the sidebar
- Track estimated costs
- Optimize queries to manage expenses

## 💡 Best Practices

### Security Monitoring

1. **Regular Reviews**: Check user activities weekly
2. **Anomaly Detection**: Look for unusual patterns or times
3. **Root Account**: Monitor for any root account usage
4. **Failed Attempts**: Investigate failed login attempts

### Risk Management

1. **Prioritize Critical and High-Risk Users**: Address users with critical risk scores first
2. **Regular Risk Assessments**: Run organization-wide risk analysis monthly
3. **Follow AI Recommendations**: Implement suggested security improvements
4. **Monitor Unused Permissions**: Regularly clean up unused permissions
5. **MFA Enforcement**: Ensure all console users have MFA enabled

### Query Optimization

1. **Start Specific**: Begin with targeted queries
2. **Use Time Limits**: Specify relevant time windows
3. **Iterate**: Refine queries based on initial results
4. **Save Patterns**: Note effective query patterns for reuse

### Compliance Management

1. **Regular Audits**: Run compliance checks monthly
2. **Document Findings**: Export reports for audit trails
3. **Track Progress**: Monitor security score improvements
4. **Address Gaps**: Prioritize high-impact compliance issues

## 🚨 Troubleshooting

### Common Issues

**No Data Showing:**
- Verify CloudTrail is enabled and logging to CloudWatch
- Check time window settings
- Confirm user has necessary permissions

**Slow Queries:**
- Reduce time window
- Use more specific search terms
- Check CloudWatch Logs service status

**Authentication Errors:**
- Verify AWS credentials are configured
- Check IAM permissions for CloudTrail and CloudWatch access
- Try manual credential override in sidebar

**Risk Assessment Issues:**
- Ensure user has IAM read permissions
- Check if CloudTrail events are available for the user
- Verify OpenAI API key for AI analysis (optional)

### Required IAM Permissions

For full functionality, ensure your AWS credentials have:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:*",
                "cloudtrail:*",
                "iam:ListUsers",
                "iam:GetUser",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListGroupsForUser",
                "iam:ListAttachedGroupPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListMFADevices",
                "iam:ListAccessKeys",
                "iam:GetLoginProfile",
                "iam:GetAccountPasswordPolicy",
                "identitystore:*",
                "sso-admin:*"
            ],
            "Resource": "*"
        }
    ]
}
```

## 📈 Advanced Features

### AI-Powered Analysis

When OpenAI API key is configured:
- Natural language summaries of user activities
- Risk assessments with detailed explanations
- Actionable security recommendations
- Context-aware threat analysis

### Data Export

- Excel reports for compliance documentation
- Customized risk assessment reports
- User activity summaries
- Security metrics tracking

### Integration Capabilities

- CloudTrail log analysis
- IAM policy evaluation
- CloudWatch Logs Insights queries
- Multi-service activity correlation

## 🔄 Regular Workflows

### Daily Security Check
1. Review high-risk alerts in Security Overview
2. Check for any root account usage
3. Monitor recent permission changes
4. Investigate any unusual activity patterns

### Weekly Risk Assessment
1. Run comprehensive risk assessment for the organization
2. Review high-risk users and follow up on recommendations
3. Check for users with unused permissions
4. Verify MFA adoption and access key rotation status

### Monthly Compliance Review
1. Export compliance reports
2. Review security score trends
3. Update security policies based on findings
4. Document remediation efforts

This enhanced dashboard now provides industry-leading IAM permission risk assessment capabilities, helping organizations maintain robust AWS security posture through comprehensive analysis and AI-powered insights. 