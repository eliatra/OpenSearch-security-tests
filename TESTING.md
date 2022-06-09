# New tests for OpenSearch security

## Basic guidelines

### Avoiding configuration chaos

- Keep tests self-contained.  All configuration shall be done declaratively inside the test classes, as close as possible to the actual tests.
- Do not create security configuration files (such as config.yml or roles.yml).

### Avoiding test flakiness

Avoid any factors that can contribute to test flakiness:

- Do not assume that the results of an indexing operation will be available right after the operation. Either use REFRESH_IMMEDIATE or use a polling construct (preferably from a common helper class). Do not just do Thread.sleep(100).
- If you create sockets, never use hardcoded port numbers. Always have a retry mechanism when creating ports.

### Keeping tests fast

- Prefer unit tests over integration tests
- For integration tests, use single node clusters whereever the tested code will not span several nodes. This will be the case for vast majority of tests.
- Avoid to use Thread.sleep()
- Avoid to write tests for something that is already being covered by other tests


