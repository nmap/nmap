# R-Map Service Detection Expansion Plan: 103 → 500+ Signatures

## Executive Summary

Based on web research and analysis of R-Map's current architecture, this plan outlines a phased approach to expand service detection from 103 signatures to 500+ signatures, achieving production parity with modern network scanners.

**Key Finding:** Nmap 7.95 (May 2024) has **12,089 service signatures** detecting **1,246 protocols**. For R-Map to be production-ready, we need to target **500-600 high-value signatures** covering the top 300+ services.

**Timeline:** 12-15 days across 5 phases
**Estimated LOC:** ~30,000 new lines of code
**Test Coverage:** 95%+ with 50+ Docker integration tests

---

## Quick Reference

| Phase | Duration | Signatures | Focus Areas |
|-------|----------|------------|-------------|
| Phase 1 | Days 1-3 | 103 (baseline) | Infrastructure refactor |
| Phase 2 | Days 4-7 | 250 (+147) | Databases, web, mail |
| Phase 3 | Days 8-10 | 400 (+150) | Cloud, queues, monitoring |
| Phase 4 | Days 11-13 | 550 (+150) | IoT, VPN, specialized |
| Phase 5 | Days 14-15 | 550 (final) | Testing & documentation |

---

[... full plan content from agent response ...]

