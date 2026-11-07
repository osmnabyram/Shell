"""shellforge core package.

Modules:
    recon       -- nmap service/version discovery and XML parsing
    matcher     -- map discovered services to candidate exploits
    executor    -- drive Metasploit over msfrpc to validate and fire candidates
    interactive -- interactive bridge to a live session over msfrpc
    reporter    -- persist attempt logs as JSON and Markdown
    colors      -- dependency-free ANSI colouring for user-facing output
"""

__all__ = ["recon", "matcher", "executor", "interactive", "reporter", "colors"]
