# VulnHunter

**VulnHunter** is an intelligent vulnerability detection tool designed to help security professionals analyze codebases and identify security risks.

## Architecture

![Architecture Diagram](./Architecture%20Diagram.drawio.svg)

## Prerequisites

**VulnHunter** uses **Docker-in-Docker (DinD)**, so **Docker** is the only dependency required to run the project.

## Quick Start

Once the container is running, open [http://localhost:5173](http://localhost:5173) in your browser to access VulnHunter.

## Acknowledgements

This project builds on the following open-source projects:

- [DREA](https://github.com/huhusmang/DREA)
- [deepagents](https://github.com/langchain-ai/deepagents)
- [codebadger](https://github.com/Lekssays/codebadger)
- [codeql-development-mcp-server](https://github.com/advanced-security/codeql-development-mcp-server)
- [semgrep](https://github.com/semgrep/semgrep)
- [docker-mcp](https://github.com/QuantGeekDev/docker-mcp)
- [docker-manager](https://github.com/DullJZ/docker-manager)

## License

![GPL v3](https://www.gnu.org/graphics/gplv3-127x51.png)