# CHATSpy Package

CHATSpy is a core Python package that provides shared functionality and utilities across all CHATS platform services. It serves as the foundation for service-to-service communication, security, and common operations.

## Description

CHATSpy is a comprehensive utility package that encapsulates common functionality used across the CHATS platform. It provides a standardized way to handle authentication, service communication, logging, and other cross-cutting concerns.

## Key Features

### Service Communication
- Service-to-service HTTP client implementations
- Kafka message broker integration
- Redis caching and state management
- Stellar blockchain integration
- Payment gateway Clients (Fiat Clients)
- Currency / Other utilities

### Security
- JWT-based authentication
- Role-based access control (RBAC)
- Service key management
- Secure token generation and validation
- Authentication middleware
- Permission management

### Utilities
- Logging and monitoring
- Health check endpoints
- IP geolocation services
- Data validation and cleaning
- Environment configuration
- Error handling and exceptions

### Data Management
- Global ID system for cross-service record identification
- Data serialization and deserialization
- Record type resolution
- Database model utilities

### Monitoring and Logging
- Structured logging
- Error tracking and alerting
- Performance monitoring
- Service health checks
- Debug and production logging configurations

## Installation

```sh
# Install from PyPI
export GITHUB_USER=<your_username>
export GITHUB_TOKEN=<token>
# Install from GitHub
pip install git+https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com/team-convexity/chatspy.git
```
