# Prompt for Creating Jules Master Task Lists

## Context
You are creating comprehensive task lists for the Jules AI agent for the OxidizedOasis-WebSands project. This is a Rust web application with Actix-web backend and Yew (WASM) frontend, with PostgreSQL database and authentication already implemented.

## Project Analysis
Based on the existing codebase, the following features are ALREADY IMPLEMENTED:
- ✅ Complete user authentication system (JWT, email verification, password reset)
- ✅ Admin panel with user management, logs, security incidents
- ✅ Frontend dashboard with multiple pages and settings
- ✅ Database schema with users, sessions, tokens, password reset
- ✅ Middleware (CORS, CSRF, rate limiting, logging, metrics)
- ✅ Health check endpoints
- ✅ Comprehensive CSS styling system
- ✅ Navigation and routing

## Task Requirements

### Database-Independent Focus
Jules struggles with database setup, so tasks should focus on:
- Frontend components and UI improvements
- Utility functions and services (backend)
- Testing frameworks and test suites
- Configuration and setup improvements
- Code quality and optimization tools
- Client-side features and enhancements
- Build and deployment tooling
- CSS/styling improvements

### Task Structure
Each task must include:
- **Branch name**: `feature/descriptive-name`
- **Time estimate**: 5-10 minutes for AI agent
- **Files to create/modify**: Specific file paths with links
- **Implementation details**: What exactly to build
- **Tests**: What tests to include
- **Success criteria**: Clear completion definition

### Batch Organization
- 10 batches of 5 tasks each (50 total per file)
- Tasks within each batch must be completely independent
- Each batch starts from the same base branch state
- Tasks can run concurrently within a batch

## Your Task

Create **JulesMaster_Part1.md** with 50 NEW tasks (Batches 1-10, Tasks M1-M50) focusing on:

### Suggested Categories for Part 1:
1. **BATCH 1**: Frontend Utility Components (M1-M5)
   - Loading spinners, toast notifications, modal dialogs, form validation, breadcrumbs

2. **BATCH 2**: Frontend Layout Components (M6-M10)
   - Responsive grid, card library, sidebar navigation, tabs, accordion

3. **BATCH 3**: Frontend Input Components (M11-M15)
   - Advanced buttons, input fields, dropdowns, checkboxes/radio, date/time pickers

4. **BATCH 4**: Frontend Data Display (M16-M20)
   - Data tables, progress indicators, badges/labels, avatars, tooltips/popovers

5. **BATCH 5**: Backend Utility Services (M21-M25)
   - String utilities, date/time utilities, file utilities, validation library, crypto utilities

6. **BATCH 6**: Frontend Animation Components (M26-M30)
   - CSS animations, transitions, scroll animations, hover effects, loading animations

7. **BATCH 7**: Frontend Theme and Styling (M31-M35)
   - Theme system, color palette, typography, spacing utilities, icon system

8. **BATCH 8**: Backend Configuration (M36-M40)
   - Environment config, logging config, API response formatter, middleware, health checks

9. **BATCH 9**: Frontend Accessibility (M41-M45)
   - Accessibility utilities, focus management, screen reader support, keyboard navigation, contrast validation

10. **BATCH 10**: Frontend Performance (M46-M50)
    - Lazy loading, virtual scrolling, memoization, debounce/throttle, bundle optimization

## File Structure Template

```markdown
# Jules Master Task List Part 1 - Database-Independent Focus

**Last Updated:** [DATE]
**Target:** 50 NEW database-independent tasks for AI autonomous agents (5-10 minutes each)
**Focus:** Frontend components, utilities, testing, tooling, and client-side features

## Overview
[Explanation of database-independent strategy and batch execution]

## **BATCH 1: [CATEGORY NAME] (Tasks M1-M5)**

- [ ] **Task M1: [Task Name]**
  - **Branch:** `feature/descriptive-name`
  - **Time:** X minutes
  - **Files:** Create [`path/to/file.rs`](path/to/file.rs), update [`existing/file.rs`](existing/file.rs)
  - **Implementation:** [Detailed description of what to build]
  - **Tests:** [What tests to include]
  - **Success:** [Clear completion criteria]

[Continue for all 50 tasks...]

## **Task Execution Guidelines for Jules AI Agent**
[Include comprehensive guidelines for execution, testing, quality requirements]
```

## Key Requirements
1. **NO database-dependent tasks** - Jules struggles with DB setup
2. **Complete independence** within batches - tasks can run concurrently
3. **Specific file paths** - Use existing project structure
4. **Realistic time estimates** - 5-10 minutes per task for AI
5. **Comprehensive tests** - Each task must include test requirements
6. **Clear success criteria** - Unambiguous completion definition
7. **Avoid duplicating existing features** - Check the implemented features list above

## Quality Standards
- All tasks must create complete, mergeable feature branches
- Include proper error handling and validation
- Follow existing code patterns and architecture
- Include accessibility compliance for frontend components
- Ensure responsive design for UI components
- Add comprehensive documentation

Create the first 50 tasks now, ensuring each is unique, valuable, and achievable by Jules without database complexity.