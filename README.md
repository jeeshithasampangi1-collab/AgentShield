# AI Agent Security Gateway

A Python-based security gateway designed to inspect and control AI agent requests before they reach tools or external destinations.

## Overview

AI agents can use tools such as weather APIs, calculators, databases, and other external services.

This project places a security layer between the AI agent and those tools.

The gateway evaluates each request and decides whether it should be:

- ALLOW
- BLOCK

## Architecture

```text
AI Agent
    |
    v
Security Gateway
    |
    +--> Risk Check
    |
    +--> Authentication
    |
    +--> Authorization
    |
    +--> Destination Check
    |
    +--> Secret Detection
    |
    +--> Prompt Injection Detection
    |
    +--> Audit Logging
    |
    v
ALLOW / BLOCK
    |
    v
Tool or API