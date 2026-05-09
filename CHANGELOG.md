# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- SSH agent authentication support: when `--ssh-key` and `--password`
  are not provided, SentinelAudit now uses `SSH_AUTH_SOCK` if
  available. Recommended over key files for production use.
