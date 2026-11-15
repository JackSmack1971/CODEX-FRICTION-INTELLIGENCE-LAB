# Repository Guidelines

## Project Structure & Module Organization

This working directory currently contains no source files, tests, or assets. Keep application code in clearly named source directories (for example, `src/`), tests in `tests/` or alongside the modules they cover, and static assets in `assets/`. Add a short README when choosing the stack and document any nonstandard layout here.

## Build, Test, and Development Commands

No build system or development commands are configured yet. When adding a project toolchain, provide reproducible install, run, and test commands in the README and keep this guide synchronized. Prefer standard project scripts, such as `npm test` or `pytest`, over undocumented machine-specific commands.

## Coding Style & Naming Conventions

Follow the formatter and linter selected for the project; do not introduce competing style tools without a clear need. Use consistent indentation and descriptive names that match the language ecosystem (for example, `snake_case` for Python modules and `camelCase` for JavaScript variables). Keep modules focused and comments useful for explaining non-obvious behavior.

## Testing Guidelines

There is no test framework or coverage requirement configured yet. Add tests with each behavior change, name them so the behavior under test is clear, and document the command contributors should run. Include regression coverage when fixing a reported defect.

## Commit & Pull Request Guidelines

This directory has no Git history, so no commit-message convention can be inferred. Use concise, imperative commit subjects (for example, `Add input validation`) until the project establishes a convention. Pull requests should explain the change and its motivation, list validation performed, link related issues when available, and include screenshots for user-facing visual changes.

## Security & Configuration

Keep credentials and machine-specific settings out of source control. Provide safe example configuration (such as `.env.example`) when needed, and document required variables without including real secrets.
