# AgentShield

## AI Agent Security Platform for Authorization Continuity, Risk-Aware Control, and Bidirectional Security

AgentShield is a security gateway architecture and Python prototype designed to protect AI-agent workflows before actions reach tools, APIs, databases, enterprise applications, files, or external services.

The central security principle is **authorization continuity**:

> **An AI agent must not automatically inherit unrestricted authority simply because a human user is authorized.**

AgentShield evaluates whether an AI agent's proposed action remains consistent with the authenticated user's authorization, requested intent, resource, operation, scope, security policies, risk signals, and behavioral context.

AgentShield also introduces **bidirectional security**. Security inspection is applied not only to actions moving from the AI agent toward a tool, but also to responses coming back from tools before they continue toward the AI agent and user.

---

## Table of Contents

1. [Overview](#overview)
2. [The Security Problem](#the-security-problem)
3. [Core Concept: Authorization Continuity](#core-concept-authorization-continuity)
4. [Complete End-to-End Architecture](#complete-end-to-end-architecture)
5. [Architecture Components](#architecture-components)
6. [Action Security Gateway](#action-security-gateway)
7. [Authorization Consistency](#authorization-consistency)
8. [Risk Engine](#risk-engine)
9. [Policy Engine](#policy-engine)
10. [Approval Control](#approval-control)
11. [Behavioral Learning](#behavioral-learning)
12. [Tool, API, and Database Boundary](#tool-api-and-database-boundary)
13. [Response Security Gateway](#response-security-gateway)
14. [Bidirectional Security](#bidirectional-security)
15. [Security Audit and Traceability](#security-audit-and-traceability)
16. [Security Decision Lifecycle](#security-decision-lifecycle)
17. [End-to-End Scenarios](#end-to-end-scenarios)
18. [Current Prototype Capabilities](#current-prototype-capabilities)
19. [Target Architecture vs. Current Implementation](#target-architecture-vs-current-implementation)
20. [Project Structure](#project-structure)
21. [API Reference](#api-reference)
22. [Data Models](#data-models)
23. [Security Controls](#security-controls)
24. [Running the Project](#running-the-project)
25. [Testing](#testing)
26. [Example Requests](#example-requests)
27. [Environment Configuration](#environment-configuration)
28. [Security and Secret Management](#security-and-secret-management)
29. [Limitations of the Current Prototype](#limitations-of-the-current-prototype)
30. [Production Evolution](#production-evolution)
31. [Future Enhancements](#future-enhancements)
32. [Design Principles](#design-principles)
33. [Project Status](#project-status)

---

# Overview

AI agents are increasingly capable of interpreting natural-language requests, selecting tools, accessing data, and taking actions on behalf of users.

This creates a new authorization problem.

Traditional authorization commonly asks:

```text
Is the user allowed to perform this action?
```

AgentShield adds another question:

```text
Is the action proposed by the AI actually consistent
with what this user requested and is authorized to do?
```

The difference is important.

A user may be authorized to:

```text
READ
sales_reports
company_sales
```

while an AI agent could propose:

```text
DELETE
customer_records
all_customers
```

The user may be authenticated.

The AI may also be authenticated.

But the proposed AI action is not necessarily authorized on behalf of that user.

AgentShield is designed to identify this discontinuity before the action reaches a protected tool or service.

---

# The Security Problem

AI agents introduce several security boundaries that traditional application authorization does not fully address by itself.

A single natural-language request can contain:

- Hidden content
- Conflicting instructions
- Prompt injection
- Obfuscation
- Requests outside the user's normal scope
- Unexpected tool selection
- Sensitive data handling
- External destinations
- High-impact operations

The AI agent then interprets the request and produces a proposed action.

The security system therefore needs to understand not only:

```text
WHO is asking?
```

but also:

```text
WHAT did the user request?

WHAT is the user authorized to do?

WHAT does the AI propose to execute?

WHERE will the action occur?

WHAT data will move?

WHAT tool will be used?

DOES the proposed action remain within the user's authorized scope?
```

AgentShield is designed around these questions.

---

# Core Concept: Authorization Continuity

Authorization continuity is the central security concept of AgentShield.

The gateway compares three security contexts:

```text
                 USER AUTHORIZATION
                        +
                 USER REQUEST / INTENT
                        +
                 AI PROPOSED ACTION
                        |
                        v
             AUTHORIZATION CONSISTENCY
```

The key question is:

> **Can this AI perform THIS action on behalf of THIS user?**

A second question is:

> **Does this action remain within the user's requested and authorized scope?**

## Example: Consistent action

User authorization:

```text
Resource: sales_reports
Operation: READ
Scope: company_sales
```

User request:

```text
Read the company sales report.
```

AI proposed action:

```text
Resource: sales_reports
Operation: READ
Scope: company_sales
Tool: database
```

The authorization and proposed action are consistent.

Expected result:

```text
ALLOW
```

## Example: Authorization discontinuity

User authorization:

```text
Resource: sales_reports
Operation: READ
Scope: company_sales
```

User request:

```text
Read the company sales report.
```

AI proposed action:

```text
Resource: customer_records
Operation: DELETE
Scope: all_customers
Tool: database
```

The AI has moved outside the user's authorized resource and requested scope.

Expected result:

```text
BLOCK
```

This is the central AgentShield security scenario.

---

# Complete End-to-End Architecture

The target AgentShield architecture is:

```text
┌─────────────────────────────────────────────────────────────────────┐
│                              USER                                  │
│                           Employee                                  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               │ Login / Identity
                               ▼
                    ┌──────────────────────────┐
                    │   IDENTITY & ACCESS      │
                    │                          │
                    │ Authentication           │
                    │ Authorization            │
                    │ User identity             │
                    │ User permissions         │
                    │ User scope                │
                    └────────────┬─────────────┘
                                 │
                          Authorized User
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │      USER REQUEST        │
                    │                          │
                    │ Normal-looking prompt    │
                    │                          │
                    │ May contain:             │
                    │ • hidden content         │
                    │ • obfuscation            │
                    │ • conflicting instructions│
                    │ • prompt injection        │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │   INPUT SECURITY LAYER   │
                    │                          │
                    │ • Prompt inspection      │
                    │ • Injection detection    │
                    │ • Obfuscation detection  │
                    │ • Input risk signals     │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                         ┌────────────────┐
                         │    AI AGENT    │
                         │                │
                         │ Interpret      │
                         │ Reason         │
                         │ Plan           │
                         │ Select Tool    │
                         └───────┬────────┘
                                 │
                                 │ PROPOSED ACTION
                                 ▼
       ┌─────────────────────────────────────────────────────────┐
       │              ACTION SECURITY GATEWAY                    │
       │                                                         │
       │  Compare three things:                                  │
       │                                                         │
       │  1. USER AUTHORIZATION                                  │
       │     What is the employee allowed to do?                 │
       │                                                         │
       │  2. USER INTENT / REQUEST                               │
       │     What did the employee actually ask for?             │
       │                                                         │
       │  3. AI PROPOSED ACTION                                  │
       │     What does the AI actually want to execute?          │
       │                                                         │
       │              ↓                                          │
       │     AUTHORIZATION CONSISTENCY CHECK                     │
       │                                                         │
       │  "Can this AI perform THIS action                       │
       │   on behalf of THIS user?"                              │
       │                                                         │
       │  "Does this action remain within the                   │
       │   user's requested and authorized scope?"              │
       └──────────────────────────┬──────────────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────┐
                    │      RISK ENGINE         │
                    │                          │
                    │ • Prompt risk            │
                    │ • Action risk             │
                    │ • Authorization mismatch │
                    │ • Scope expansion        │
                    │ • Tool sensitivity       │
                    │ • Destination risk       │
                    │ • Data sensitivity       │
                    │ • Behavioral anomaly     │
                    └────────────┬─────────────┘
                                 │
                           Risk / Policy
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
                ▼                ▼                ▼
             LOW RISK       MEDIUM RISK       HIGH RISK
                │                │                │
                ▼                ▼                ▼
             CONTINUE         APPROVAL          DENY
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │    APPROVAL CONTROL      │
                    │                          │
                    │ Human approval           │
                    │ OR                       │
                    │ Authorized approver      │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │    FINAL POLICY ENGINE   │
                    │                          │
                    │ Risk                     │
                    │ + Authorization          │
                    │ + User scope             │
                    │ + Action                 │
                    │ + Approval               │
                    │ + Security policy        │
                    │                          │
                    │ ALLOW / DENY / ESCALATE  │
                    └────────────┬─────────────┘
                                 │
                              ALLOW
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │        TOOL / API / DB        │
                 │                               │
                 │ • Database                   │
                 │ • API                        │
                 │ • Enterprise application     │
                 │ • File system                │
                 │ • External service           │
                 └──────────────┬────────────────┘
                                │
                                │ RESPONSE
                                ▼
              ┌────────────────────────────────────────┐
              │         RESPONSE SECURITY GATEWAY      │
              │                                        │
              │ Inspect what comes BACK from the tool  │
              │                                        │
              │ • Response inspection                  │
              │ • Response injection detection        │
              │ • Sensitive-data detection             │
              │ • Unexpected instructions              │
              │ • Response risk                        │
              │ • Response-to-action consistency       │
              └────────────────────┬───────────────────┘
                                   │
                            Safe response?
                                   │
                         ┌─────────┴─────────┐
                         │                   │
                        YES                  NO
                         │                   │
                         ▼                   ▼
                     AI AGENT          BLOCK / ESCALATE
                         │
                         ▼
                       USER
```

---

# Architecture Components

## 1. User / Employee

The user initiates the workflow.

The security system needs to understand the identity and authority of that user before an AI agent acts on the user's behalf.

---

## 2. Identity & Access

The Identity & Access layer represents:

- Authentication
- User identity
- Authorization
- User permissions
- User scope

The current prototype accepts user identity and authorization context as part of the request model and authenticates AI agents using configured API keys.

A production implementation can integrate with enterprise identity systems and IAM platforms.

---

## 3. User Request

The user request contains the natural-language instruction and optional structured context.

The current request model can represent:

```text
prompt
requested_resource
requested_operation
requested_scope
```

The request can be used to establish what the user intended before the AI produces an action.

---

## 4. Input Security Layer

The target architecture includes an input security layer responsible for inspecting the user's input.

Potential signals include:

- Prompt injection
- Hidden content
- Obfuscation
- Conflicting instructions
- Input risk

The current prototype contains prompt-injection/security checks in the request-security path.

A dedicated advanced obfuscation-detection subsystem is part of the target architecture and future evolution.

---

## 5. AI Agent

The AI agent represents the reasoning and planning component.

The conceptual flow is:

```text
User request
     ↓
AI interprets request
     ↓
AI reasons
     ↓
AI plans
     ↓
AI selects tool
     ↓
AI creates proposed action
```

The current prototype accepts a structured proposed action as an input to the gateway. This allows the security layer to be developed and tested independently of a specific LLM provider or orchestration framework.

---

# Action Security Gateway

The Action Security Gateway is the central outbound security boundary.

It evaluates the proposed AI action before the action is allowed to proceed toward a tool.

The gateway compares:

```text
1. User authorization
2. User request / intent
3. AI proposed action
```

The primary security question is:

```text
Does the AI action remain consistent with
the user's authority and requested scope?
```

---

# Authorization Consistency

The current implementation provides explicit authorization-consistency checks.

A proposed action contains:

```text
resource
operation
scope
tool
destination
data
```

The authorization context contains:

```text
resource
operations
scope
```

The gateway evaluates:

### Resource match

Does the proposed resource match an authorized resource?

### Operation match

Is the proposed operation included in the user's authorized operations?

### Scope match

Does the proposed scope remain within the authorized scope?

The current implementation produces explicit signals including:

```text
authorized
authorization_mismatch
resource_mismatch
operation_mismatch
scope_expansion
reason
```

---

# Risk Engine

The Risk Engine converts security signals into a numeric risk score.

The current prototype considers signals including:

- Tool risk
- External destination
- Sensitive data
- Authorization mismatch
- Resource mismatch
- Operation mismatch
- Scope expansion
- Behavioral anomaly

Current prototype risk contributions include:

```text
Tool baseline:
weather                    +5
calculator                +10
database                  +30

External destination      +10

Sensitive data            +20

Authorization mismatch   +25
Resource mismatch         +15
Operation mismatch        +30
Scope expansion           +20
Behavioral anomaly        +20
```

These scores are additive.

For example:

```text
Database tool
+ Authorization mismatch
+ Resource mismatch

30 + 25 + 15 = 70
```

The demonstrated authorization-continuity attack therefore produced:

```text
risk_score = 70
decision = BLOCK
```

---

# Policy Engine

The policy engine converts risk into a policy outcome.

The current prototype defines:

```text
Risk < 20
    ↓
ALLOW
```

```text
Risk 20–39
    ↓
APPROVAL
```

```text
Risk >= 40
    ↓
DENY
```

The gateway also evaluates agent/tool permissions and other security controls before finalizing the request.

The policy layer is therefore separate from the risk calculation:

```text
Security signals
      ↓
Risk Engine
      ↓
Risk score
      ↓
Policy Engine
      ↓
Decision
```

---

# Approval Control

Medium-risk requests can enter a human approval workflow.

The current prototype maintains pending approval requests and supports:

```text
APPROVE
DENY
```

An approval request can contain:

```text
request_id
user_id
agent_id
tool
action
risk_score
approval_required
approver
approver_authority
approval_decision
reason
```

The approval lifecycle is:

```text
Request
  ↓
Risk evaluation
  ↓
APPROVAL_REQUIRED
  ↓
Human / authorized approver
  ↓
APPROVED or DENIED
```

Explicit human approval is also used by the behavioral-learning component as an approved-action signal.

---

# Behavioral Learning

AgentShield includes a prototype behavioral-learning component.

Approved actions can be recorded as a behavioral history.

The history contains:

```text
user_id
resource
operation
scope
tool
```

Future actions are compared against the user's established history.

If an action matches the established baseline:

```text
anomaly_detected = false
```

If the action differs from the baseline:

```text
anomaly_detected = true
anomaly_score = 20
```

The current implementation uses an in-memory history.

This is a prototype design. A production implementation would require persistent storage, privacy controls, retention policies, and more sophisticated behavioral modeling.

---

# Tool, API, and Database Boundary

The target architecture places the actual tool or service behind the policy decision.

Potential protected targets include:

- Databases
- APIs
- Enterprise applications
- File systems
- External services

The intended enforcement pattern is:

```text
AI proposed action
       ↓
AgentShield
       ↓
ALLOW
       ↓
Protected tool
```

or:

```text
AI proposed action
       ↓
AgentShield
       ↓
BLOCK / APPROVAL
       ↓
Tool is not allowed to receive the action
```

The current prototype primarily implements and tests the gateway decision layer. Real production tool execution and enterprise integrations are part of the target architecture and future implementation.

---

# Response Security Gateway

Security does not stop after a tool is allowed to execute.

A tool response can contain malicious or sensitive content.

The Response Security Gateway therefore inspects what comes back from the protected service.

The current response-security component checks for:

### Response injection

Suspicious phrases include indicators such as:

```text
ignore previous instructions
ignore all instructions
ignore your instructions
system prompt
reveal your instructions
reveal the system prompt
bypass security
disable security
override security
```

### Sensitive response data

The current implementation checks for indicators such as:

```text
password
api_key
apikey
secret
access_token
access token
```

The response risk calculation currently assigns:

```text
Response injection       +50
Sensitive response data  +30
```

A response can therefore be blocked before continuing toward the AI/user workflow.

---

# Bidirectional Security

The core bidirectional concept is:

```text
OUTBOUND SECURITY

User
 ↓
AI Agent
 ↓
AgentShield
 ↓
Tool / API / DB
```

and:

```text
INBOUND SECURITY

Tool / API / DB
 ↓
Response Security
 ↓
AgentShield
 ↓
AI Agent
 ↓
User
```

This means AgentShield is designed to inspect both:

1. **What the AI wants to do**
2. **What the tool sends back**

This is important because a secure outbound action can still receive an unsafe response.

---

# Security Audit and Traceability

Security auditing is a core part of AgentShield.

The audit layer records security-relevant metadata for decisions.

Current audit fields include:

```text
timestamp
request_id
user_id
agent
tool
action
destination
risk_score
decision
reason
authorization_scope
proposed_action
authorization_consistency
approval_request
outcome
```

The purpose is to provide a traceable security decision path.

A security reviewer should be able to understand:

```text
Who initiated the request?
        ↓
Which agent acted?
        ↓
What was requested?
        ↓
What did the AI propose?
        ↓
What authorization existed?
        ↓
What risk was detected?
        ↓
Was approval required?
        ↓
Who approved or denied?
        ↓
What was the final decision?
        ↓
What was the outcome?
```

The logging design favors security metadata and reason codes rather than unnecessarily storing sensitive prompt or business data.

---

# Security Decision Lifecycle

The intended lifecycle is:

```text
1. User authenticates
        ↓
2. User authorization is established
        ↓
3. User submits request
        ↓
4. Input security inspects request
        ↓
5. AI interprets and plans
        ↓
6. AI creates proposed action
        ↓
7. AgentShield authenticates the agent
        ↓
8. Authorization consistency is evaluated
        ↓
9. Behavioral context is evaluated
        ↓
10. Risk is calculated
        ↓
11. Policy decision is made
        ↓
12. ALLOW / APPROVAL / DENY
        ↓
13. If approved, protected tool can execute
        ↓
14. Tool returns response
        ↓
15. Response Security Gateway inspects response
        ↓
16. Safe response continues toward AI
        ↓
17. AI returns result to user
        ↓
18. Security event is audited
```

---

# End-to-End Scenarios

## Scenario 1: Authorized Database Read

### User authorization

```json
{
  "resource": "sales_reports",
  "operations": ["READ"],
  "scope": "company_sales"
}
```

### User request

```text
Read the company sales report.
```

### AI proposed action

```json
{
  "resource": "sales_reports",
  "operation": "READ",
  "scope": "company_sales",
  "tool": "database"
}
```

### Authorization consistency

```text
authorized: true
authorization_mismatch: false
resource_mismatch: false
operation_mismatch: false
scope_expansion: false
```

### Result

```text
ALLOW
```

This demonstrates that AgentShield can allow an action that remains consistent with the user's authority.

---

# Scenario 2: Authorization Continuity Attack

### User authorization

```text
READ sales_reports
scope: company_sales
```

### User request

```text
Read the company sales report.
```

### AI proposed action

```text
DELETE customer_records
scope: all_customers
```

### AgentShield result

```text
authorization_mismatch: true
resource_mismatch: true
```

Current prototype risk:

```text
Database tool             +30
Authorization mismatch    +25
Resource mismatch         +15
--------------------------------
Total                     70
```

Final result:

```text
risk_score: 70
policy_decision: DENY
decision: BLOCK
```

This is the primary authorization-continuity demonstration.

---

# Scenario 3: Operation Mismatch

A second authorization-continuity pattern is:

```text
User authorization:
sales_reports → READ → company_sales
```

while the AI proposes:

```text
sales_reports → DELETE → company_sales
```

Here the resource remains the same, but the operation changes.

This allows the gateway to detect an operation-level mismatch.

The current risk model assigns an additional:

```text
operation_mismatch = +30
```

---

# Scenario 4: Scope Expansion

Authorized scope:

```text
Region A
```

AI proposed scope:

```text
All regions
```

The gateway can identify:

```text
scope_expansion = true
```

The current risk model assigns:

```text
scope_expansion = +20
```

This allows AgentShield to detect an AI action that attempts to broaden the user's original authority.

---

# Scenario 5: External Destination

An action targeting an external destination can increase risk.

Examples include destinations containing:

```text
http://
https://
.com
.net
.org
```

The current prototype adds:

```text
external destination = +10
```

This is one of the signals considered before the policy decision.

---

# Scenario 6: Sensitive Data

The gateway checks action data for indicators such as:

```text
password
api_key
apikey
secret
access_token
access token
```

Sensitive-data detection adds:

```text
+20
```

This can combine with other signals such as external destinations or authorization mismatches.

---

# Scenario 7: Malicious Tool Response

A tool can return content that attempts to influence the AI.

For example, a response containing:

```text
ignore previous instructions
```

is treated as a response-injection signal.

Current response risk:

```text
Response injection = +50
```

The response can therefore be blocked by the Response Security Gateway.

---

# Scenario 8: Sensitive Tool Response

If a tool response contains indicators such as:

```text
password
api_key
secret
access_token
```

the response-security layer adds:

```text
Sensitive response data = +30
```

The response can be blocked based on the resulting security decision.

---

# Current Prototype Capabilities

The current AgentShield prototype implements and tests the following core capabilities:

```text
✓ Agent authentication
✓ Agent/tool permission checks
✓ User identity context
✓ User authorization context
✓ User request context
✓ Proposed action model
✓ Authorization consistency checking
✓ Resource mismatch detection
✓ Operation mismatch detection
✓ Scope expansion detection
✓ Risk scoring
✓ Policy decisions
✓ Approval workflow
✓ Approval approval/denial
✓ Duplicate approval protection
✓ Invalid approval decision handling
✓ Behavioral baseline analysis
✓ Behavioral anomaly detection
✓ Response injection detection
✓ Sensitive response detection
✓ Audit logging
✓ End-to-end security tests
```

---

# Target Architecture vs. Current Implementation

AgentShield has a broader end-to-end architecture than the current prototype implementation.

This distinction is intentional.

## Currently implemented

The prototype currently implements the core security gateway layer:

```text
Agent authentication
        ↓
Authorization context
        ↓
Proposed action
        ↓
Authorization consistency
        ↓
Behavioral analysis
        ↓
Risk engine
        ↓
Policy engine
        ↓
Approval control
        ↓
Audit logging
```

It also provides response-security inspection:

```text
Tool response
        ↓
Response injection detection
        ↓
Sensitive-data detection
        ↓
Response risk
        ↓
ALLOW / BLOCK
```

## Target / future components

The complete architecture also envisions deeper implementations for:

```text
• Enterprise identity-provider integration
• Full AI-agent orchestration
• Dedicated obfuscation detection
• Advanced semantic user-intent analysis
• Real tool/API/database execution
• Response-to-action semantic consistency
• Persistent behavioral learning
• Enterprise policy administration
• Production approval services
• SIEM/security analytics integration
• Enterprise-scale policy enforcement
```

The README intentionally distinguishes these future components from currently implemented prototype functionality.

---

# Project Structure

```text
AgentShield/
│
├── main.py
├── models.py
│
├── auth.py
├── authorization_consistency.py
├── risk_engine.py
├── policy_engine.py
├── approval_control.py
├── behavioral_learning.py
├── response_security.py
├── audit_logger.py
│
├── destination_checker.py
├── secret_detector.py
├── prompt_injection.py
│
├── tests/
│   └── test_security_gateway.py
│
├── .env
├── .gitignore
└── README.md
```

## Core modules

### `main.py`

FastAPI application and orchestration layer.

Coordinates:

- Authentication
- Authorization consistency
- Risk calculation
- Policy decisions
- Approval workflow
- Behavioral analysis
- Response security
- Audit logging

### `models.py`

Defines request and response data structures using Pydantic models.

Important models include:

```text
UserAuthorization
UserRequestContext
ProposedAction
AgentRequest
ToolResponse
ApprovalDecisionRequest
```

### `auth.py`

Provides agent API-key authentication.

### `authorization_consistency.py`

Compares the proposed action against the user's authorized:

```text
resource
operation
scope
```

### `risk_engine.py`

Calculates the security risk score from multiple signals.

### `policy_engine.py`

Converts risk into:

```text
ALLOW
APPROVAL
DENY
```

and manages agent/tool permissions.

### `approval_control.py`

Creates and processes pending human approval decisions.

### `behavioral_learning.py`

Maintains the prototype behavioral history and detects deviations from established approved behavior.

### `response_security.py`

Inspects tool responses for:

- Response injection
- Sensitive information

### `audit_logger.py`

Writes security events to the audit log.

---

# API Reference

## `POST /check-request`

The primary action-security endpoint.

It evaluates an AI agent request before the proposed action can continue.

### Main security checks

```text
1. Agent authentication
2. Agent/tool authorization
3. Destination security
4. Secret detection
5. Prompt injection detection
6. User authorization
7. Authorization consistency
8. Behavioral analysis
9. Risk calculation
10. Policy decision
11. Audit logging
```

### Possible outcomes

```text
ALLOW
APPROVAL_REQUIRED
BLOCK
```

---

## `POST /approval/{request_id}`

Processes a pending approval request.

The request contains:

```text
approver
approver_authority
decision
```

Supported decisions include:

```text
APPROVE
DENY
```

The endpoint also prevents a pending approval from being processed multiple times.

---

## `POST /check-response`

Evaluates a tool/API response.

Security checks include:

```text
Response injection
Sensitive response data
Response risk
```

Possible outcome:

```text
ALLOW
BLOCK
```

---

# Data Models

## UserAuthorization

Represents what the user is authorized to do.

```text
resource
operations
scope
```

Example:

```json
{
  "resource": "sales_reports",
  "operations": ["READ"],
  "scope": "company_sales"
}
```

---

## UserRequestContext

Represents the user's request and structured request context.

```text
prompt
requested_resource
requested_operation
requested_scope
```

---

## ProposedAction

Represents the action the AI proposes to execute.

```text
resource
operation
scope
tool
destination
data
```

---

## AgentRequest

Represents the gateway request.

It includes:

```text
agent
tool
action
api_key
destination
data
user_id
user_request
user_authorizations
proposed_action
```

---

## ToolResponse

Represents data returned from a protected tool.

```text
agent
tool
response_data
```

---

## ApprovalDecisionRequest

Represents a human approval decision.

```text
approver
approver_authority
decision
```

---

# Security Controls

AgentShield combines several security controls rather than relying on a single detector.

## Authentication

The agent must provide a valid configured API key.

---

## Authorization

The gateway checks whether the agent is permitted to use the requested tool.

---

## Authorization Consistency

The proposed action is compared against the user's authorized resource, operation, and scope.

---

## Prompt Injection Detection

The request-security layer checks for known prompt-injection indicators.

---

## Destination Security

External destinations can increase risk.

---

## Secret Detection

Potential secrets in action data can increase risk.

---

## Behavioral Analysis

Actions can be compared against an established approved-action baseline.

---

## Response Security

Tool responses are inspected for injection and sensitive-data indicators.

---

## Audit Logging

Security events are recorded for traceability.

---

# Running the Project

## Prerequisites

The current development environment uses:

- Windows
- Anaconda / Conda
- Python
- FastAPI
- Uvicorn
- Pytest
- HTTPX
- python-dotenv

The project environment used during development is:

```text
ai-security
```

---

## Step 1: Activate the environment

```bash
conda activate ai-security
```

---

## Step 2: Navigate to the project

```bash
cd "C:\Users\jeesh\OneDrive\Documents\ai-agent-security-gateway"
```

---

## Step 3: Start the FastAPI server

```bash
uvicorn main:app --reload
```

The application runs locally at:

```text
http://127.0.0.1:8000
```

---

## Step 4: Open API documentation

Open:

```text
http://127.0.0.1:8000/docs
```

FastAPI's Swagger interface can be used to execute and inspect the gateway endpoints.

---

# Testing

Run the complete test suite with:

```bash
pytest -q
```

The current validated project checkpoint produced:

```text
60 passed
```

There were also two dependency deprecation warnings from the FastAPI/Starlette/AnyIO testing stack. These warnings did not represent test failures.

The test suite covers the security gateway behavior across authentication, authorization, risk, policy, approval, behavioral analysis, response security, audit logging, and end-to-end attack scenarios.

---

# Example Requests

## Authorized request

```json
{
  "agent": "demo-agent",
  "tool": "database",
  "action": "READ sales_reports",
  "api_key": "demo-secret-key",
  "user_id": "user-001",
  "user_request": {
    "prompt": "Read the company sales report",
    "requested_resource": "sales_reports",
    "requested_operation": "READ",
    "requested_scope": "company_sales"
  },
  "user_authorizations": [
    {
      "resource": "sales_reports",
      "operations": ["READ"],
      "scope": "company_sales"
    }
  ],
  "proposed_action": {
    "resource": "sales_reports",
    "operation": "READ",
    "scope": "company_sales",
    "tool": "database"
  }
}
```

Expected behavior:

```text
ALLOW
```

---

# Authorization Continuity Attack Example

```json
{
  "agent": "demo-agent",
  "tool": "database",
  "action": "DELETE customer_records",
  "api_key": "demo-secret-key",
  "user_id": "user-001",
  "user_request": {
    "prompt": "Read the company sales report",
    "requested_resource": "sales_reports",
    "requested_operation": "READ",
    "requested_scope": "company_sales"
  },
  "user_authorizations": [
    {
      "resource": "sales_reports",
      "operations": ["READ"],
      "scope": "company_sales"
    }
  ],
  "proposed_action": {
    "resource": "customer_records",
    "operation": "DELETE",
    "scope": "all_customers",
    "tool": "database"
  }
}
```

Expected behavior:

```text
BLOCK
```

The current demonstrated risk calculation is:

```text
Database tool             +30
Authorization mismatch    +25
Resource mismatch         +15
--------------------------------
Total                      70
```

---

# Environment Configuration

AgentShield uses environment variables for agent API keys.

Example:

```text
DEMO_AGENT_API_KEY=demo-secret-key
LIMITED_AGENT_API_KEY=limited-secret-key
```

These values are intended for local development and testing.

Production deployments should use a dedicated secret-management system.

---

# Security and Secret Management

Never commit real secrets to Git.

The project uses a `.env` file for local environment configuration.

The `.env` file should be excluded from Git using `.gitignore`.

Production deployments should use secure secret storage rather than hard-coded credentials.

Potential production options include:

```text
Enterprise secret manager
Cloud secret manager
Vault-style secret management
Managed identity
Short-lived credentials
Workload identity
```

---

# Audit and Privacy Considerations

Security logging should provide enough information to investigate security decisions without unnecessarily collecting sensitive user content.

Recommended audit principles include:

- Store security-relevant metadata
- Store reason codes
- Store request identifiers
- Store authorization outcomes
- Store policy decisions
- Avoid unnecessary sensitive prompt content
- Apply retention policies
- Restrict access to audit logs
- Protect logs from unauthorized modification

A production implementation should also consider privacy requirements and organizational retention policies.

---

# Limitations of the Current Prototype

AgentShield is currently a security-gateway prototype rather than a production enterprise security platform.

Important limitations include:

## In-memory behavioral history

Behavioral history currently exists in application memory.

Restarting the application can clear the history.

A production implementation would require persistent storage.

---

## Simulated AI proposed action

The current API accepts a structured `proposed_action`.

The prototype does not require a specific LLM provider.

This is intentional because it allows the security gateway to be tested independently.

A future implementation can connect the gateway directly to an AI-agent orchestration framework.

---

## No production tool execution engine yet

The current prototype evaluates whether an action should be allowed.

It does not yet provide a full production execution framework for every possible:

```text
Database
API
Enterprise application
File system
External service
```

---

## Input obfuscation is a target capability

The complete architecture includes obfuscation detection.

The current prototype does not yet implement a dedicated generalized obfuscation detector.

---

## Full semantic intent analysis is future work

The current implementation represents user request context structurally.

A production implementation could add deeper semantic comparison between:

```text
Natural-language user intent
        ↓
AI interpretation
        ↓
Structured proposed action
```

---

## Response-to-action consistency is a target capability

The architecture includes response-to-action consistency.

The current response-security implementation focuses on response injection and sensitive-data detection.

A future version can perform deeper semantic validation of whether the returned data is consistent with the approved action.

---

# Production Evolution

A production-oriented AgentShield deployment could evolve into a distributed security control plane.

A possible future architecture is:

```text
                         USER
                           │
                           ▼
                  ENTERPRISE IDENTITY
                           │
                           ▼
                     USER REQUEST
                           │
                           ▼
                  INPUT SECURITY
                           │
                           ▼
                       AI AGENT
                           │
                           ▼
                 PROPOSED ACTION
                           │
                           ▼
              ┌─────────────────────────┐
              │       AGENTSHIELD       │
              │                         │
              │ Identity                │
              │ Authorization           │
              │ Intent                  │
              │ Policy                  │
              │ Risk                    │
              │ Behavioral Analysis     │
              │ Approval                │
              │ Audit                   │
              └────────────┬────────────┘
                           │
                    Policy Decision
                           │
              ┌────────────┼────────────┐
              │            │            │
            ALLOW       APPROVAL       DENY
              │            │
              │        Human Review
              │            │
              └──────┬─────┘
                     │
                     ▼
              TOOL / API / DB
                     │
                     ▼
              RESPONSE SECURITY
                     │
              ┌──────┴──────┐
              │             │
             SAFE          UNSAFE
              │             │
              ▼             ▼
           AI AGENT     BLOCK / ESCALATE
              │
              ▼
             USER
```

Potential production integrations include:

- Enterprise identity providers
- IAM systems
- PAM systems
- SIEM platforms
- Policy engines
- Databases
- Enterprise APIs
- Cloud services
- Security analytics platforms
- Approval systems
- Persistent behavioral analytics

---

# Future Enhancements

Future development areas include:

## 1. Real AI-agent integration

Connect AgentShield to an actual AI-agent framework so that the gateway automatically receives structured actions generated by an AI model.

---

## 2. Real tool execution

Implement controlled adapters for:

```text
Database
REST API
Enterprise application
File system
External service
```

The gateway should enforce its decision before execution.

---

## 3. Enterprise identity integration

Integrate with enterprise identity and access systems.

The goal is to obtain authoritative user identity and permissions instead of relying only on request-provided authorization context.

---

## 4. Advanced intent analysis

Compare:

```text
User natural-language intent
        ↓
AI interpretation
        ↓
Proposed structured action
```

This can provide stronger protection against subtle intent drift.

---

## 5. Obfuscation detection

Add dedicated detection for encoded or intentionally obscured instructions.

---

## 6. Persistent behavioral learning

Move behavioral history from memory into controlled persistent storage.

Potential enhancements include:

- Baseline management
- Time-aware behavior
- Role-aware behavior
- Resource sensitivity
- Confidence scores
- Explainable anomaly reasons

---

## 7. Response-to-action consistency

Validate whether the tool response is consistent with the action that was actually approved.

For example:

```text
Approved:
READ sales_reports

Unexpected response:
customer_passwords
```

The response should be treated as inconsistent even if it does not contain an obvious prompt-injection phrase.

---

## 8. Security analytics

Integrate audit events with security monitoring platforms.

This can enable:

- Security dashboards
- Investigation
- Correlation
- Alerting
- Incident response
- Compliance reporting

---

# Design Principles

AgentShield is guided by several principles.

## Least privilege

AI agents should operate within the minimum authority required for the requested task.

---

## Authorization continuity

The AI's authority should remain connected to the user's actual authorization.

---

## Explicit scope

Resources, operations, and scopes should be represented explicitly whenever possible.

---

## Defense in depth

No single detector should be responsible for the entire security decision.

AgentShield combines:

```text
Identity
Authorization
Intent
Action analysis
Risk
Policy
Behavior
Approval
Response security
Audit
```

---

## Human control for higher-risk actions

Higher-risk actions can require human intervention rather than relying entirely on autonomous AI decisions.

---

## Bidirectional security

Security inspection should cover both:

```text
AI → Tool
```

and:

```text
Tool → AI
```

---

## Explainability

Security decisions should provide understandable reasons such as:

```text
Authorization mismatch
Resource mismatch
Operation mismatch
Scope expansion
Sensitive data
External destination
Behavioral anomaly
Response injection
```

---

## Auditability

Security decisions should produce traceable records that allow investigators to understand what happened and why.

---

# Project Status

AgentShield is an active security-gateway prototype.

Current validated capabilities include:

```text
✓ Agent authentication
✓ Tool authorization
✓ User authorization context
✓ Proposed-action modeling
✓ Authorization consistency
✓ Resource mismatch detection
✓ Operation mismatch detection
✓ Scope expansion detection
✓ Risk scoring
✓ Policy decisions
✓ Human approval workflow
✓ Behavioral anomaly analysis
✓ Response injection detection
✓ Sensitive-response detection
✓ Security audit logging
✓ End-to-end automated tests
```

Current test checkpoint:

```text
60 tests passed
```

The broader architecture continues toward:

```text
Identity
   ↓
User intent
   ↓
AI reasoning
   ↓
Authorization continuity
   ↓
Risk
   ↓
Policy
   ↓
Human approval when required
   ↓
Controlled tool execution
   ↓
Response security
   ↓
AI
   ↓
User
   ↓
Audit
```

---

# Final Security Model

AgentShield can be summarized by one principle:

> **The AI agent should only be able to act within the authority that can legitimately be attributed to the user, the request, the approved scope, and the security policy.**

The platform therefore treats an AI agent not as an automatically trusted extension of the user, but as an actor whose proposed actions must continuously satisfy security controls.

```text
USER
  ↓
IDENTITY
  ↓
AUTHORITY
  ↓
REQUEST
  ↓
AI INTERPRETATION
  ↓
PROPOSED ACTION
  ↓
AUTHORIZATION CONTINUITY
  ↓
RISK
  ↓
POLICY
  ↓
APPROVAL / ALLOW / DENY
  ↓
TOOL / API / DB
  ↓
RESPONSE SECURITY
  ↓
AI
  ↓
USER
```

**AgentShield — Security control for the next generation of AI agents.**
